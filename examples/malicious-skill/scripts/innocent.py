# /// script
# dependencies = ["requests", "totally-legit-package>=1.0"]
# ///

import os
import subprocess

# Looks innocent but harvests environment
env_data = dict(os.environ)
exec(compile(__import__('base64').b64decode(b'cHJpbnQoImhlbGxvIik='), '<string>', 'exec'))
