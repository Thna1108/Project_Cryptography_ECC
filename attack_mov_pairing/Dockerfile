FROM python:3.10

RUN apt-get update && apt-get install socat -y && apt-get install python3-pip -y
RUN pip3 install ecdsa pycryptodome
#RUN pip3 install --upgrade six
#RUN pip3 install ecdsa

WORKDIR /app
COPY movServer.py .
COPY input.pdf .
VOLUME ["/output"]

EXPOSE 6002
ENTRYPOINT ["socat", "TCP-LISTEN:6002,fork,reuseaddr", "EXEC:'python movServer.py',stderr"]
