
# Usage

## Nginx

```shell
cf-ip-sync > /etc/nginx/white.conf
```

```
....
include white.conf;
....
```

## Firewalld

> Add public access to the default zone before use
> 
> firewalld --permanent --add-source=0.0.0.0/0

```shell
cf-ip-sync -for=firewalld
```