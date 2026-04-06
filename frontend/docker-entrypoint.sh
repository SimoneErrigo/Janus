#!/bin/sh
# Substitute only selected vars in nginx config, leaving nginx variables intact
envsubst '${API_BACKEND} ${FRONTEND_BIND}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
