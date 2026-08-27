import os

import json

from typing import List


class Config:

    def __init__(self, config_path: str = './config.json'):

        self.config_path = config_path

        self.load_config()

        

    def load_config(self):

        if os.path.exists(self.config_path):

            with open(self.config_path, 'r') as f:

                self.config = json.load(f)

        else:

            self.config = {}

            

        # Set defaults

        self.db_path = self.config.get('db_path', './vx0id.db')

        self.log_file = self.config.get('log_file', './vx0id.log')

        self.log_level = self.config.get('log_level', 'INFO')

        self.allowed_targets = self.config.get('allowed_targets', [])

        self.allow_private = self.config.get('allow_private', False)

        self.rate_limit = self.config.get('rate_limit', 10)  # requests per minute

        self.bind_address = self.config.get('bind_address', '127.0.0.1')

        self.port = self.config.get('port', 8080)

        self.api_token = self.config.get('api_token', None)
