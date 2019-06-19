# Phish Redirector

phishredirector facilitates the migration away from Phish Protection without worrying about the URLS that 
have been rewritten becoming inaccessible. 

## Installation

Clone the repository

Request from the following information from support

```
$pp_public_id     = '';
$pp_shared_secret = '';
```

Configure your web server and SSL certificate to match your existing link rewriting URL. This code
can be run on the smallest VPS. 

The index page should be accessible in the web root `/` folder

## Requirements

Funcational Web Server (Nginx / Apache / Caddy) with PHP7 support

## Usage

- Update your CNAME to point to your new webserver
- Ensure that SSL is enabled
- Copy and paste an existing re-written link and check your logs to see if your new server processed the request.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
