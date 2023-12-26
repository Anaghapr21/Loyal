FROM python:3.10
WORKDIR /loyal

# Copying and installing dependencies first
COPY requirements.txt /loyal/
RUN pip install -r /loyal/requirements.txt

# Copying the rest of the application code
COPY . /loyal/

CMD ["python","manage.py","runserver","0.0.0.0:8000"]