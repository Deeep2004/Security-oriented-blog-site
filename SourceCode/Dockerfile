FROM python:3.8

ENV HOME /root
ENV TZ=America/New_York
# set time zone for the time of the posts
WORKDIR /root

COPY . .
# Download dependancies
RUN pip3 install -r requirements.txt

EXPOSE 8080

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u app.py




