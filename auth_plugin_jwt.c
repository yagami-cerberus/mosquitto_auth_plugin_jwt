#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mosquitto_plugin.h>

#include <jwt.h>
#include "auth_plugin_jwt.h"


#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_AUTH 11
#define MOSQ_ERR_PLUGIN_DEFER 17


struct Settings settings = {
    "sub",
    NULL
};


bool verify_jwt_exp(jwt_t *token) {
    return jwt_get_grant_int(token, "exp") > time(NULL);
}


bool verify_jwt_iat(jwt_t *token) {
    return jwt_get_grant_int(token, "iat") < time(NULL);
}


bool verify_mqtt_username(jwt_t *token, const char *username) {
    const char *sub = jwt_get_grant(token, settings.username_attribute);
    return sub && !strcmp(sub, username);
}


bool verify_jwt_token(jwt_t *token, const char *username) {
    if (!verify_jwt_exp(token)) {
        fprintf(stderr, "User %s 'exp' verify failed\n", username);
        return false;
    }
    if (!verify_jwt_iat(token)) {
        fprintf(stderr, "User %s 'iat' verify failed\n", username);
        return false;
    }
    if (!verify_mqtt_username(token, username)) {
        fprintf(stderr, "User %s username verify failed\n", username);
        return false;
    }
    return true;
}


int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
{
    struct SignKey *last_key = NULL;
    FILE *fd;

    int i=0;
    for (; i<opt_count; i++) {
        fprintf(stderr, "AuthOptions: key=%s, val=%s\n", opts[i].key, opts[i].value);

        if (!strncmp(opts[i].key, "jwt_key_", 8)) {
            const char *filename = strchr(opts[i].value, ' ') + 1;

            fd = fopen(filename, "r");
            if (fd) {
                char *name = malloc(sizeof(char) * (strlen(opts[i].key - 7)));
                char *kid = malloc(sizeof(char) * (filename - opts[i].value));

                strcpy(name, opts[i].key + 8);
                strncpy(kid, opts[i].value, (filename - opts[i].value - 1));
                kid[filename - opts[i].value - 1] = 0;

                fseek(fd, 0L, SEEK_END);
                int keysize = ftell(fd);
                unsigned char *keybuffer = malloc(keysize);
                rewind(fd);
                fread(keybuffer, keysize, 1, fd);

                if (last_key == NULL) {
                    settings.keys = last_key = malloc(sizeof(struct SignKey));
                } else {
                    last_key->next = malloc(sizeof(struct SignKey));
                    last_key = last_key -> next;
                }

                last_key->name = name;
                last_key->kid = kid;
                last_key->keybuffer = keybuffer;
                last_key->keysize = keysize;
                last_key->next = NULL;

            } else {
                fprintf(stderr, "Can not read key file from auth_opt_%s: %s\n", opts[i].key, strerror(errno));
            }
        }
        else if (!strncmp(opts[i].key, "jwt_username_attribute", 22)) {
            settings.username_attribute = opts[i].value;
        }
    }
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
{
    settings.username_attribute = "sub";
    struct SignKey *key = settings.keys;
    while (key) {
        free(key->name);
        free(key->kid);
        free(key->keybuffer);
        key = key->next;
    }
    settings.keys = NULL;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
    return MOSQ_ERR_PLUGIN_DEFER;
}

int mosquitto_auth_unpwd_check(void *user_data, const struct mosquitto *client, const char *username, const char *password)
{
    if (username == NULL || password == NULL) {
        return MOSQ_ERR_AUTH;
    }

    struct SignKey *sign_key;
    jwt_t *token;
    int ret;

    ret = jwt_decode(&token, password, NULL, 0);
    if (ret) {
        fprintf(stderr, "decode error: %d\n", ret);
    }

    const char* kid = jwt_get_header(token, "kid");

    sign_key = settings.keys;
    while (sign_key) {
        if (!strcmp(sign_key->kid, kid)) {
            jwt_free(token);
            ret = jwt_decode(&token, password, sign_key->keybuffer, sign_key->keysize);

            if (!ret) {
                bool verify = verify_jwt_token(token, username);
                jwt_free(token);
                if (verify) {
                    return MOSQ_ERR_SUCCESS;
                } else {
                    return MOSQ_ERR_AUTH;
                }
            } else {
                fprintf(stderr, "User %s jwt verify failed: %d\n", username, ret);
                jwt_free(token);
                return MOSQ_ERR_AUTH;
            }
        } else {
            sign_key = sign_key->next;
        }
    }
    fprintf(stderr, "User %s verify failed, kid not match, kid: %s\n", username, kid);
    jwt_free(token);
    return MOSQ_ERR_AUTH;
}

int mosquitto_auth_psk_key_get(void *user_data, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
    return MOSQ_ERR_AUTH;
}
