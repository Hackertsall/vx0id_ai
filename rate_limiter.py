import time

import threading

from typing import Dict

from vx0id.config import Config


class RateLimiter:

    def __init__(self, limit: int):

        self.limit = limit

        self.tokens = {}

        self.lock = threading.Lock()

        

    def limit(self, func):

        """Rate limiting decorator"""

        def wrapper(*args, **kwargs):

            with self.lock:

                current_time = time.time()

                if args[0] not in self.tokens:

                    self.tokens[args[0]] = {

                        'count': 0,

                        'reset_time': current_time + 60

                    }

                    

                if current_time >= self.tokens[args[0]]['reset_time']:

                    self.tokens[args[0]] = {

                        'count': 0,

                        'reset_time': current_time + 60

                    }

                    

                if self.tokens[args[0]]['count'] >= self.limit:

                    return {"error": "Rate limit exceeded"}, 429

                    

                self.tokens[args[0]]['count'] += 1

                return func(*args, **kwargs)

        return wrapper
