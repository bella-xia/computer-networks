# include <stdio.h>
#include <errno.h>

int main(int argc, char **argv) {
    FILE *textFile, *binaryFile;
    char character, *txt_name;
    char *binary_name = "output.bin";
    

    if (argc < 2) {
        fprintf(stderr, "Usage: ./binary [txtfilename.txt] [binaryfilename.bin]\n");
        return 1;
    }

    txt_name = argv[1];
    if (argc > 2) {
        binary_name = argv[2];
    }

    textFile = fopen(txt_name, "r");
    if (textFile == NULL) {
        fprintf(stderr, "Error opening %s: %s\n", txt_name, strerror(errno));
        return 2;
    }

    binaryFile = fopen(binary_name, "wb");
    if (binaryFile == NULL) {
         fprintf(stderr, "Error opening %s: %s\n", binary_name, strerror(errno));
         return 3;
    }

    while ((character = fgetc(textFile)) != EOF) {
        fwrite(&character, sizeof(char), 1, binaryFile);
    }

    fclose(textFile);
    fclose(binaryFile);
    
    printf("Binary file created successfully.\n");
    return 0;
}