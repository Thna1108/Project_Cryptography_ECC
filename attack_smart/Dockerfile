FROM python:3.10
FROM sagemath/sagemath:latest

RUN sudo apt-get update && sudo apt-get install socat -y && sudo apt-get install python3-pip -y
RUN sage --pip install pycryptodome
#RUN pip3 install --upgrade six
#RUN pip3 install ecdsa

COPY serverSmart.sage .
COPY test.txt .
VOLUME ["/output"]

EXPOSE 8888
ENTRYPOINT ["socat", "TCP-LISTEN:8888,fork,reuseaddr", "EXEC:'sage serverSmart.sage',stderr"]