# import os
# from app import create_app

# app = create_app()

# if __name__ == "__main__":
#     app.run()

import os
import sys

# Add your project directory to the Python path
project_home = '/var/www/Lastbit_jobs'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import the application
from app import create_app
application = create_app()

if __name__ == "__main__":
    application.run()