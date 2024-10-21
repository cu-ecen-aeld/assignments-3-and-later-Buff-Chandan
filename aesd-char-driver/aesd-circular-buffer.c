/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset. Any necessary locking must be performed by the caller.
 * @param char_offset the position to search for in the buffer list, describing the zero-referenced
 *      character index if all buffer strings were concatenated end to end.
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte offset of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset. This value is only set when a matching char_offset is found
 *      in the aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    // Check for invalid input, return NULL if input is invalid
    if (buffer == NULL)
    {
        return NULL;
    }
    
    if (entry_offset_byte_rtn == NULL)
    {
        return NULL;
    }

    size_t total_size = 0;  // Initialize total size of characters
    uint8_t index = buffer->out_offs;  // Start from the oldest entry
    uint8_t count;

    // find how many entries are in the buffer
    if (buffer->full)
    {
        count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    {
        count = buffer->in_offs - buffer->out_offs;
    }

    // Traverse through the buffer entries
    while (count > 0)
    {
        // Add size of the current buffer entry to the total
        total_size += buffer->entry[index].size;

        // If entry that contains the desired char_offset was found
        if (total_size > char_offset)
        {
            // Calculate the byte offset within the found entry
            *entry_offset_byte_rtn = char_offset - (total_size - buffer->entry[index].size);

            // Return the corresponding buffer entry
            return &buffer->entry[index];
        }

        // Move to the next entry
        if (index == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)
        {
            index = 0;  // Wrap around to the start
        }
        else
        {
            index++;  // Move to the next index
        }

        // Decrease the count of remaining entries to check
        count--;
    }

    // when the char_offset was not found, return NULL
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // Check for invalid input, return if input is invalid
    if (buffer == NULL)
    {
        return;
    }
    
    if (add_entry == NULL)
    {
        return;
    }

    // Add new entry at the current in_offs position
    memcpy(&buffer->entry[buffer->in_offs], add_entry, sizeof(struct aesd_buffer_entry));

    // move ahead the in_offs pointer, wrap around when necessary
    if (buffer->in_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)
    {
        buffer->in_offs = 0;  // Wrap around to the start
    }
    else
    {
        buffer->in_offs++;  // Move to the next index
    }

    // If the buffer is full, also move out_offs to the next position
    if (buffer->full)
    {
        if (buffer->out_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)
        {
            buffer->out_offs = 0;  // Wrap around to the start
        }
        else
        {
            buffer->out_offs++;  // Move to the next index
        }
    }

    // Check if the buffer is now full
    if (buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    // Set all values in the buffer structure to 0
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}

