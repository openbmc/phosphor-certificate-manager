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
CERT_KEY_FILE: File contains Certificate and private in .pem format.
CERT_FILE

#### Upload LDAP client certificate
```
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream" \
     -X PUT -T <CERT_KEY_FILE> \
     https://<BMC_IP>/xyz/openbmc_project/certs/client/ldap
```

#### Upload NGINX server certificate
```
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream" \
     -X PUT -T <CERT_KEY_FILE> \
     https://<BMC_IP>/xyz/openbmc_project/certs/server/https
```

#### Upload LDAP CA certificate
```
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream" \
     -X PUT -T <CERT_FILE> \
     https://<BMC_IP>/xyz/openbmc_project/certs/authority/ldap
```

#### Delete LDAP client certificate
```
curl -c cjar -b cjar -k -X DELETE \
     https://<BMC_IP>/xyz/openbmc_project/certs/client/ldap
```

#### Delete https server certificate
```
curl -c cjar -b cjar -k -X DELETE \
     https://<BMC_IP>/xyz/openbmc_project/certs/server/https 
```

#### Delete https CA certificate
```
curl -c cjar -b cjar -k -X DELETE \
     https://<BMC_IP>/xyz/openbmc_project/certs/authority/ldap
