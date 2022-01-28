FROM public.ecr.aws/lambda/python:3.9

USER root
RUN yum install -y yum-utils
RUN yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
RUN yum -y install terraform
RUN pip3 install requests boto3

# work somewhere where we can write
COPY bin/linux/tfsec-linux-amd64 /usr/bin/tfsec
COPY bitbucket_api.py /usr/bin/bitbucket_api.py 

WORKDIR /src

# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "tfsec" ]
# as we specified an entrypoint, this is appended as an argument (i.e., `tfsec --help`)
CMD [ "--help" ]
