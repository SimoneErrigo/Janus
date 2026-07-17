#!/bin/sh
# Substitute only selected vars in nginx config, leaving nginx variables intact
envsubst '${API_BACKEND} ${API_BACKEND_PORT} ${FRONTEND_BIND} ${FRONTEND_PORT} ${FRONTEND_ROOT}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
