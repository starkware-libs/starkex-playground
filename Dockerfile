FROM ciimage/python:3.9
RUN sed -i -e 's/http:\/\/archive\.ubuntu\.com\/ubuntu\//mirror:\/\/mirrors\.ubuntu\.com\/mirrors\.txt/' /etc/apt/sources.list

# Python and pip.
RUN apt update
RUN apt install -y wget python3.9-dev python3-pip

# Copy files.
COPY . /app/
WORKDIR /app/
RUN chmod a+x player.py

# Install python packages.
RUN python3.9 -m pip install --upgrade pip
RUN python3.9 -m pip install -r scripts/requirements.txt
