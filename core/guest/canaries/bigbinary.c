/* V7: the produced binary is bounded (compile stage). 8 MiB of initialized data. */
static const unsigned char blob[8u << 20] = {1};

int main(void) { return blob[sizeof blob - 1]; }
