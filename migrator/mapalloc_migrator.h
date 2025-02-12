#ifndef MAPALLOC_MIGRATOR_H_
#define MAPALLOC_MIGRATOR_H_

/**
 * Checks whether the migration has already happened.
 *
 * @return 1 if the migration has already happened, 0 otherwise
 */
unsigned char has_migrated(void);


/**
 * Manually triggers the migration process
 *
 * @param fd A file descriptor for a MAPAlloc allocator interface file
 * @param stack_size_limit The maximum stack size. Pass 0 to limit the stack to its current size
 * @return 0 upon success, or a negative value if the migration failed
 */
int migrate_all(int fd, unsigned long stack_size_limit);

#endif
