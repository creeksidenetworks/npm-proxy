# Ngix Proxy with Oauth2-Proxy


## Register your application in Azure portal

- Registration values

| Redirect URIs | https://auth.yourdomain/oauth2/callback |
|------------|------------|
| Application (client) ID |  |
| Directory (tenant) ID |  |
| Client Secretes |  |


- Generate cookie random password
```bash
dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d -- '\n' | tr -- '+/' '-_'; echo
```

- Update docker-compose.yaml

| OAUTH2_PROXY_COOKIE_SECRET | The random passwd we just generated |
|------------|------------|
| OAUTH2_PROXY_COOKIE_DOMAINS | Your base domain |
| OAUTH2_PROXY_WHITELIST_DOMAINS | Your base domain |
| OAUTH2_PROXY_CLIENT_ID | Azure Application (client) ID |
| OAUTH2_PROXY_CLIENT_SECRET | Azure Client Secretes |
| OAUTH2_PROXY_EMAIL_DOMAINS | Your email domain, auzre default email doamin |
| OAUTH2_PROXY_AZURE_TENANT | Azure Directory (tenant) ID |
| OAUTH2_PROXY_OIDC_ISSUER_URL | https://login.microsoftonline.com/<Azure Directory (tenant) ID>/v2.0/ |
| OAUTH2_PROXY_REDIRECT_URL | Azure Redirect URIs |

## Launch containers

```bash
docker compose up -d
```

## NPM Adavnced Configurations

### Oauth2-proxy

Proxy Host: http://oauth2proxy:4180

```nginx
proxy_buffers 8 16k;
proxy_buffer_size 32k;

location /oauth2/ {
    proxy_pass http://oauth2proxy:4180;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Scheme $scheme;
    proxy_set_header X-Auth-Request-Redirect $scheme://$host$request_uri;
  }

  location /oauth2/auth {
    proxy_pass http://oauth2proxy:4180;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Scheme $scheme;
    proxy_set_header Content-Length   "";
    proxy_pass_request_body off;
  }

  location / {
    try_files $uri $uri/ =404;
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in?rd=https://$host$request_uri;
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;
  }


```

### FreeIPA

```nginx
proxy_buffers 8 16k;
proxy_buffer_size 32k;

location /oauth2/ {
    proxy_pass           http://oauth2proxy:4180;
    proxy_set_header     Host                    $host;
    proxy_set_header     X-Real-IP               $remote_addr;
    proxy_set_header     X-Scheme                $scheme;
    proxy_set_header     X-Auth-Request-Redirect $request_uri;
}

location = /oauth2/auth {
    proxy_pass           http://oauth2proxy:4180;
    proxy_set_header     Host             $host;
    proxy_set_header     X-Real-IP        $remote_addr;
    proxy_set_header     X-Scheme         $scheme;

    # nginx auth_request includes headers but not body
    proxy_set_header     Content-Length   "";
    proxy_pass_request_body off;
}  
  
location / {
    proxy_pass              https://freeipa.creekside.lcl/;
    proxy_set_header        Referer https://freeipa.creekside.lcl/ipa/ui;
    proxy_cookie_domain     freeipa.creekside.lcl ipa.fmt.creekside.network;

    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in?rd=https://$host$request_uri;
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;
    auth_request_set $token  $upstream_http_x_auth_request_access_token;
    proxy_set_header X-Access-Token $token;
}
```


### VMWare ESXi

```nginx
proxy_buffers 8 16k;
proxy_buffer_size 32k;

location /oauth2/ {
    proxy_pass           http://oauth2proxy:4180;
    proxy_set_header     Host                    $host;
    proxy_set_header     X-Real-IP               $remote_addr;
    proxy_set_header     X-Scheme                $scheme;
    proxy_set_header     X-Auth-Request-Redirect $request_uri;
}

location = /oauth2/auth {
    proxy_pass           http://oauth2proxy:4180;
    proxy_set_header     Host             $host;
    proxy_set_header     X-Real-IP        $remote_addr;
    proxy_set_header     X-Scheme         $scheme;

    # nginx auth_request includes headers but not body
    proxy_set_header     Content-Length   "";
    proxy_pass_request_body off;
}

location / {
    proxy_pass          https://10.1.50.202/;

    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
    
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in?rd=https://$host$request_uri;
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;
    auth_request_set $token  $upstream_http_x_auth_request_access_token;
    proxy_set_header X-Access-Token $token;
}

```
### Dell iDRAC 9

Note: Web console is not supported, use VNC instead.

```nginx
location / {
        proxy_pass https://10.1.50.102;
        proxy_set_header Host 10.1.50.102;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_ssl_verify off;
        proxy_ssl_server_name on;

        # Rewrite embedded iDRAC IP in Virtual Console URLs
        sub_filter 'https://10.1.50.102' 'https://idrac2.fmt.creekside.network';
        sub_filter 'http://10.1.50.102' 'https://idrac2.fmt.creekside.network';
        sub_filter_once off;
        sub_filter_types text/html text/javascript text/css application/javascript;

}
```

### NoVNC

```nginx
location /vnc01/ {
        proxy_pass http://10.1.53.101:6081/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /vnc02/ {
        proxy_pass http://10.1.53.101:6082/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
```
