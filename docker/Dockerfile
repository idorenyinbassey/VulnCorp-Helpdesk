# VulnCorp Helpdesk - Docker app image
#
# Uses the official php:8.2-apache image on a normal internet connection.
# (Verified during development against a locally-built equivalent - see
# docker/README.md for why, and docker/Dockerfile.devtest for the exact
# substitute used to confirm this Dockerfile's logic actually works.)
FROM php:8.2-apache

RUN docker-php-ext-install mysqli \
    && a2enmod rewrite

WORKDIR /var/www/html

# Copy the whole app in. .dockerignore keeps .git, docker/, and other
# non-runtime files out of the image.
COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && mkdir -p /var/www/html/uploads \
    && chmod -R 777 /var/www/html/uploads

EXPOSE 80
