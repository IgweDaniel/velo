#!/usr/bin/env bash
# exit on error
set -o errexit

poetry config virtualenvs.path venv && source $(poetry env info --path)/bin/activate
# Run any pending migrations and collect static files
# python manage.py collectstatic --no-input
python manage.py makemigrations app
python manage.py migrate app
python manage.py migrate

# Seed data
# python manage.py seed data.json

# Execute the main container command (run the Django app)
exec "$@"
