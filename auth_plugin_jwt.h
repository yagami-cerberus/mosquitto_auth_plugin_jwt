
struct SignKey {
    char *name;
    char *kid;
    unsigned char *keybuffer;
    int keysize;
    struct SignKey *next;
};


struct Settings {
    char *username_attribute;
    struct SignKey *keys;
};
