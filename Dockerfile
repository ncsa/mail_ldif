FROM python:3

ENV TZ=America/Chicago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir /home/mail_ldif

COPY . /mail_ldif
WORKDIR /mail_ldif
RUN python -m pip install -r /mail_ldif/requirements.txt

CMD ["bash"]