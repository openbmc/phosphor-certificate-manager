# phosphor-certificate-manager
Certificate management allows to replace the existing certificate and private
key file with another (possibly CA signed) Certificate key file. Certificate
management allows the user to install both the server and client certificates.

## To Build
```
To build this package, do the following steps:

    1. ./bootstrap.sh
    2. ./configure ${CONFIGURE_FLAGS}
    3. make

To clean the repository run `./bootstrap.sh clean`.
```

## REST use-cases

BMC_IP: BMC IP address
FILE: File contains Certificate and private in .pem format.

#### Upload LDAP client certificate
```
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream"
     -X PUT -T <FILE> https://<BMC_IP>/xyz/openbmc_project/certs/client/ldap
```

#### Upload NGINX server certificate
```
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream"             
     -X PUT -T <FILE> https://<BMC_IP>/xyz/openbmc_project/certs/client/https    
```

#### Delete LDAP client certificate
```
curl -c cjar -b cjar -k -X DELETE \
     https://<BMC_IP>/xyz/openbmc_project/certs/server/ldap
```

#### Delete https server certificate                                             
```                                                                             
curl -c cjar -b cjar -k -X DELETE \                                             
     https://<BMC_IP>/xyz/openbmc_project/certs/server/https 
```
