import json

import logging

import os

import sqlite3

import hashlib

import secrets

from datetime import datetime

from contextlib import contextmanager

from typing import Dict, List, Optional, Generator

from vx0id.scanners import ScannerModule

from vx0id.config import Config


class VX0ID:

    def __init__(self, config: Config):

        self.config = config

        self.logger = self.setup_logging()

        self.init_db()

        

    @contextmanager

    def get_db_connection(self) -> Generator[sqlite3.Connection, None, None]:

        """Context manager for database connections with auto-closing"""

        conn = sqlite3.connect(self.config.db_path)

        try:

            yield conn

        finally:

            conn.close()

    

    def setup_logging(self) -> logging.Logger:

        logger = logging.getLogger('vx0id')

        logger.setLevel(self.config.log_level)

        handler = logging.FileHandler(self.config.log_file)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        handler.setFormatter(formatter)

        logger.addHandler(handler)

        return logger

    

    def init_db(self):

        with self.get_db_connection() as conn:

            cursor = conn.cursor()

            

            # Migration check

            cursor.execute("PRAGMA table_info(auth_keys)")

            columns = [info[1] for info in cursor.fetchall()]

            if 'api_key' in columns:

                cursor.execute("ALTER TABLE auth_keys RENAME TO auth_keys_old")

                cursor.execute('''

                    CREATE TABLE auth_keys (

                        id INTEGER PRIMARY KEY,

                        api_key_hash TEXT UNIQUE NOT NULL,

                        owner TEXT NOT NULL,

                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

                    )

                ''')

                cursor.execute('''

                    INSERT INTO auth_keys (id, api_key_hash, owner) 

                    SELECT id, api_key, owner FROM auth_keys_old

                ''')

                cursor.execute("DROP TABLE auth_keys_old")

            

            # Create tables

            cursor.execute('''

                CREATE TABLE IF NOT EXISTS targets (

                    id INTEGER PRIMARY KEY,

                    name TEXT UNIQUE NOT NULL,

                    ip TEXT NOT NULL,

                    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP

                )

            ''')

            

            cursor.execute('''

                CREATE TABLE IF NOT EXISTS auth_keys (

                    id INTEGER PRIMARY KEY,

                    api_key_hash TEXT UNIQUE NOT NULL,

                    owner TEXT NOT NULL,

                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

                )

            ''')

            

            cursor.execute('''

                CREATE TABLE IF NOT EXISTS audit_log (

                    id INTEGER PRIMARY KEY,

                    target_id INTEGER,

                    action TEXT NOT NULL,

                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    result TEXT,

                    consent_ref TEXT,

                    FOREIGN KEY(target_id) REFERENCES targets(id)

                )

            ''')

            

            conn.commit()

    

    def validate_ip(self, ip: str) -> bool:

        """Validate IP against allowed targets and private IP restrictions"""

        if ip in self.config.allowed_targets:

            return True

        if self.config.allow_private:

            return True

        return not (ip.startswith('10.') or 

                   ip.startswith('192.168.') or

                   ip.startswith('127.') or

                   ip.startswith('169.254.') or

                   ip.startswith('224.'))  # Multicast

    

    def add_target(self, name: str, ip: str, consent_ref: str) -> int:

        """Add target with validation and consent logging"""

        if not self.validate_ip(ip):

            self.logger.warning(f"Invalid IP rejected: {ip}")

            return 0

            

        try:

            with self.get_db_connection() as conn:

                cursor = conn.cursor()

                cursor.execute(

                    'INSERT OR REPLACE INTO targets (name, ip) VALUES (?, ?)',

                    (name, ip)

                )

                conn.commit()

                target_id = cursor.lastrowid

                

                # Log consent

                cursor.execute(

                    'INSERT INTO audit_log (target_id, action, consent_ref) VALUES (?, ?, ?)',

                    (target_id, 'consent_added', consent_ref)

                )

                conn.commit()

                return target_id

        except Exception as e:

            self.logger.error(f"Failed to add target: {e}")

            return 0

    

    def verify_defensive_checks(self, target_id: int, consent_ref: str) -> Dict:

        """Run real verification modules"""

        with self.get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute('SELECT ip FROM targets WHERE id = ?', (target_id,))

            target_ip = cursor.fetchone()

            if not target_ip:

                return {'state': 'error', 'message': 'Target not found'}

                

            ip = target_ip[0]

            scanner = ScannerModule()

            

            results = {

                'state': 'completed',

                'checks': {}

            }

            

            # Run verification modules

            for module_name, module_func in scanner.modules.items():

                try:

                    module_results = module_func(ip)

                    if module_results['status'] == 'success':

                        results['checks'][module_name] = module_results

                    else:

                        results['checks'][module_name] = {

                            'status': 'not_implemented',

                            'reason': 'Module not implemented'

                        }

                except Exception as e:

                    results['checks'][module_name] = {

                        'status': 'error',

                        'message': str(e)

                    }

            

            # Log successful check

            cursor.execute(

                'INSERT INTO audit_log (target_id, action, result, consent_ref) VALUES (?, ?, ?, ?)',

                (target_id, 'defensive_check', json.dumps(results), consent_ref)

            )

            conn.commit()

            return results

    

    def get_authorized_keys(self) -> List[Dict]:

        with self.get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute('SELECT id, owner FROM auth_keys')

            return [{'id': row[0], 'owner': row[1]} for row in cursor.fetchall()]

    

    def generate_api_key(self, owner: str) -> Dict:

        """Generate and store API key hash, return only raw key once"""

        raw_key = secrets.token_hex(32)

        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        

        with self.get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute(

                'INSERT INTO auth_keys (api_key_hash, owner) VALUES (?, ?)',

                (key_hash, owner)

            )

            conn.commit()

            

        return {

            'raw_key': raw_key,

            'hash': key_hash

        }

    

    def authenticate(self, api_key: str) -> Optional[str]:

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        

        with self.get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute(

                'SELECT owner FROM auth_keys WHERE api_key_hash = ?',

                (key_hash,)

            )

            result = cursor.fetchone()

            return result[0] if result else None
