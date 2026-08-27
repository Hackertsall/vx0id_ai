import argparse

import json

from vx0id.core import VX0ID

from vx0id.config import Config


class CLI:

    def __init__(self, config: Config):

        self.config = config

        self.vx0id = VX0ID(config)

        

    def parse_args(self):

        parser = argparse.ArgumentParser(description='vx0id - HexStrike AI Clone')

        subparsers = parser.add_subparsers(dest='command')

        

        # Register target command

        register_parser = subparsers.add_parser('register', help='Register a target')

        register_parser.add_argument('--name', required=True, help='Target name')

        register_parser.add_argument('--ip', required=True, help='Target IP')

        register_parser.add_argument('--consent-ref', required=True, help='Consent reference')

        

        # Request scan command

        scan_parser = subparsers.add_parser('scan', help='Request a scan')

        scan_parser.add_argument('--target-id', type=int, required=True, help='Target ID')

        scan_parser.add_argument('--consent-ref', required=True, help='Consent reference')

        

        return parser.parse_args()

        

    def execute_command(self, args):

        if args.command == 'register':

            target_id = self.vx0id.add_target(

                args.name, 

                args.ip, 

                args.consent_ref

            )

            print(f"Target registered with ID: {target_id}")

            

        elif args.command == 'scan':

            results = self.vx0id.verify_defensive_checks(

                args.target_id,

                args.consent_ref

            )

            print(json.dumps(results, indent=2))

            

    def run(self):

        args = self.parse_args()

        self.execute_command(args)
