import os

# Define the 'config' variable which points to our parser configuration file.
# This is a variable that MWCP will look for.
config = os.path.join(os.path.dirname(__file__), '.parser_config.yml')