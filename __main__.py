from vx0id.cli import CLI

from vx0id.config import Config


if __name__ == '__main__':

    config = Config()

    cli = CLI(config)

    cli.run()
