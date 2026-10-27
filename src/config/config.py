import os
from dotenv import find_dotenv, load_dotenv

# Load environment variables early so config() can find them
load_dotenv(find_dotenv())

class Config:
    def __call__(self, key, default=None, cast=None):
        return self.get(key, default=default, cast=cast)

    def get(self, key, default=None, cast=None):
        value = os.environ.get(key, default)
        if cast and value is not None:
            if cast == bool:
                if isinstance(value, bool):
                    return value
                return str(value).lower() in ("true", "1", "yes")
            try:
                return cast(value)
            except (ValueError, TypeError):
                return default
        return value

config = Config()
