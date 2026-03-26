#!/bin/sh
# Substitute only API_BACKEND in nginx config, leaving nginx variables intact
envsubst '${API_BACKEND}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
