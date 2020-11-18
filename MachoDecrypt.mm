//
//
//
//
//
//
//

#import "MachoDecrypt.h"

#include <stdio.h>
#include <sys/stat.h>
#include <objc/runtime.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach-o/ldsyms.h>

#pragma mark - Functions

#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24))
int _macho_start(const char *image_name, const char *binary_Name, const char *sandbox_path, int image_index, completion_block_t completion);
void _macho_decrypt_path(char **path, const char *binary_Name, const char *to_path);
int _macho_copy_image(const char *image, const char *to_path);

#pragma mark - Public

void macho_decrypt_binary(const char *binary_Name, const char *sandbox_path, completion_block_t completion) {
    uint32_t numberOfImages = _dyld_image_count();
    for (int i = 0; i < numberOfImages; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (strstr(imageName, binary_Name) != NULL) {
            _macho_start(imageName, binary_Name, sandbox_path, i, completion);
        }
    }
}

#pragma mark - Private

int _macho_start(const char *image_name, const char *binary_Name, const char *sandbox_path, int image_index, completion_block_t completion) {
    DLog(@"Decrypting image: %s", image_name);

    int return_code = 0;

    struct mach_header *header = (struct mach_header *)_dyld_get_image_header(image_index);
    if (!header) { 
        DLog(@"Failed: No header");

        completion(-1);
        return -1;
    }

    // Get load command
    struct load_command *command = NULL;
    uint32_t magic_number = header->magic;
    if (magic_number == MH_MAGIC_64) {
        command = (struct load_command *)((unsigned char *)header + sizeof(struct mach_header_64));
    }
    else if (magic_number == MH_MAGIC) {
        command = (struct load_command *)((unsigned char *)header + sizeof(struct mach_header));
    }
    else {
        DLog(@"Failed: No magic number");

        completion(-1);
        return -1;
    }

    // Loop commands
    for (int i = 0; i < header->ncmds; i++) {
        // Check for encryption command
        if (command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command *encryption_command = (struct encryption_info_command *)command;

            uint32_t cryptid = encryption_command->cryptid;
            if (cryptid == 0) {
                DLog(@"Info: Not ecnrypted, skipping");

                completion(-1);
                return -1;
            }

            // Copy image to override later
            char *decrypted_path = NULL;
            _macho_decrypt_path(&decrypted_path, binary_Name, sandbox_path);
            if (_macho_copy_image(image_name, decrypted_path) != 0) {
                DLog(@"Failed: to copy: %s", binary_Name);

                free(decrypted_path);

                completion(-1);
                return -1;
            }

           // get cyptid offset
            unsigned int off_cryptid = (off_t)((off_t)(void *)&cryptid - (off_t)(void *)header);
            DLog(@"Offset to cryptid (%d) found in memory @ %p (from %p). off_cryptid = %u (0x%x)\n", cryptid, &cryptid, header, off_cryptid, off_cryptid);

            // Open encrypted image
            int image_name_fd = open(image_name, O_RDONLY);
            if (image_name_fd == -1) { 
                DLog(@"Failed: to open %s", image_name);

                free(decrypted_path);

                completion(-1);
                return -1;
            }

            // Read image into buffer for the header info
            char image_buffer[1024];
            int read_bytes = read(image_name_fd, (void *)image_buffer, sizeof(image_buffer));
            if (read_bytes != sizeof(image_buffer)) { 
                DLog(@"Failed: to read %s", image_name);

                free(decrypted_path);
                close(image_name_fd);

                completion(-1);
                return -1;
            }

            // Build file offset
            int file_offset = 0;
            struct fat_header *f_header = (struct fat_header *)image_buffer;
            uint32_t f_magic_number = f_header->magic;
            if (f_magic_number == FAT_CIGAM) {
                struct fat_arch *arch = (struct fat_arch *)&f_header[1];
                for (int j = 0; j < swap32(f_header->nfat_arch); j++) {
                    if ((header->cputype == swap32(arch->cputype)) && (header->cpusubtype == swap32(arch->cpusubtype))) {
                        file_offset = swap32(arch->offset);
                        DLog(@"Info: Arch offset 0x%x", file_offset);
                        break;
                    }

                    arch++;
                }

                if (file_offset == 0) {
                    DLog(@"Failed: No valid offset in FAT_CIGAM");

                    free(decrypted_path);
                    close(image_name_fd);

                    completion(-1);
                    return -1;
                }
            }
            else if (f_magic_number == MH_MAGIC || f_magic_number == MH_MAGIC_64) {
                file_offset = 0;
            } 
            else {
                DLog(@"Failed: no magic number");

                free(decrypted_path);
                close(image_name_fd);

                completion(-1);
                return -1;
            }

            // Find out sizes
            size_t encrypted_offset = file_offset + encryption_command->cryptoff;
            int file_remainder = lseek(image_name_fd, 0, SEEK_END) - (encrypted_offset + encryption_command->cryptsize);    
            lseek(image_name_fd, 0, SEEK_SET);

            char *start_buffer = (char *)malloc(encrypted_offset);
            if (read(image_name_fd, start_buffer, encrypted_offset) != encrypted_offset) {
                DLog(@"Failed: to read %s", image_name);

                free(decrypted_path);
                free(start_buffer);
                close(image_name_fd);

                completion(-1);
                return -1;
            }
            
            // Open output
            int decrypted_path_fd = open(decrypted_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (decrypted_path_fd == -1) { 
                DLog(@"Failed: to open %s", decrypted_path);

                free(decrypted_path);
                free(start_buffer);
                close(image_name_fd);

                completion(-1);
                return -1;
            }

            // Write to output
            if (write(decrypted_path_fd, start_buffer, encrypted_offset) != encrypted_offset) {
                DLog(@"Failed: to write %s", decrypted_path);

                free(decrypted_path);
                free(start_buffer);
                close(image_name_fd);
                close(decrypted_path_fd);

                completion(-1);
                return -1;
            }

            // Free buffer
            free(start_buffer);
            start_buffer = NULL;

            // Now write decrypted data
            if (write(decrypted_path_fd, (unsigned char *)header + encryption_command->cryptoff, encryption_command->cryptsize) != encryption_command->cryptsize) {
                DLog(@"Failed: to write decrypted data %s", decrypted_path);

                free(decrypted_path);
                close(image_name_fd);
                close(decrypted_path_fd);

                completion(-1);
                return -1;
            }

            // Read the last of the file
            char *end_buffer = (char *)malloc(file_remainder);
            lseek(image_name_fd, encryption_command->cryptsize, SEEK_CUR);

            if (read(image_name_fd, end_buffer, file_remainder) != file_remainder) {
                DLog(@"Failed: to read %s", image_name);

                free(decrypted_path);
                free(end_buffer);
                close(image_name_fd);
                close(decrypted_path_fd);

                completion(-1);
                return -1;
            }

            // Write the last of the file
            if (write(decrypted_path_fd, end_buffer, file_remainder) != file_remainder) {
                DLog(@"Failed: to write the last of the data data %s", decrypted_path);

                free(decrypted_path);
                free(end_buffer);
                close(image_name_fd);
                close(decrypted_path_fd);
                
                completion(-1);
                return -1;
            }

            // Free buffer
            free(end_buffer);
            end_buffer = NULL;
            
            // Set LC_ENCRYPTION_INFO->cryptid  to 0
            if (off_cryptid) {
                off_cryptid += encrypted_offset;
                
                DLog(@"Info: Set cryptid to 0 at offset 0x%x", off_cryptid);
                if (lseek(decrypted_path_fd, off_cryptid, SEEK_SET) == off_cryptid) {
                    uint32_t zero_byte = 0;
                    if (write(decrypted_path_fd, &zero_byte, 4) != 4) {
                        DLog(@"Info: Did not set cryptid");
                    }
                } 
                else {
                    DLog(@"Info: Did not set cryptid");
                }
            }

            // Close files
            close(image_name_fd);
            close(decrypted_path_fd);
            sync();

            // Free decrypted path
            free(decrypted_path);
            decrypted_path = NULL;
        }

        command = (struct load_command *)((unsigned char *)command + command->cmdsize);
    }

    completion(0);
    return 0;

}

void _macho_decrypt_path(char **path, const char *binary_Name, const char *to_path) {
    size_t to_path_length = strlen(to_path) + strlen(binary_Name) + 12;
    char *new_path = (char *)malloc(to_path_length);
    asprintf(&new_path, "%s/%s-Decrypted", to_path, binary_Name);
    
    *path = new_path;
}

int _macho_copy_image(const char *image, const char *to_path) {
    DLog(@"Copy %s -> %s", image, to_path);

    FILE *image_file = fopen(image, "r");
    if (!image_file) return -1;

    FILE *new_image = fopen(to_path, "w");
    if (!new_image) return -1;

    do { 
        char file_byte = fgetc(image_file); 
        fputc(file_byte, new_image); 

    } 
    while (!feof(image_file)); 

    struct stat image_stat;
    stat(image, &image_stat);
    struct stat new_image_stat;
    stat(image, &new_image_stat);
    
    DLog(@"Image sizes: s-> %lld d-> %lld ", image_stat.st_size, new_image_stat.st_size);

    fclose(image_file); 
    image_file= NULL;

    fclose(new_image); 
    new_image = NULL;   

    return 0;
}