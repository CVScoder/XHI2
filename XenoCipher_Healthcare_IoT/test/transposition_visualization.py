import matplotlib.pyplot as plt
import matplotlib.animation as animation
import numpy as np

# Simplified Python version of transposition cipher for visualization
class KeyedPRNG:
    def __init__(self, key16):
        a = int.from_bytes(key16[:8], 'big')
        b = int.from_bytes(key16[8:], 'big')
        self.s = a ^ ((b << 1) | (b >> 63)) ^ 0x9E3779B97F4A7C15
        if self.s == 0:
            self.s = 0xDEADBEEFC0FFEE

    def next64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        z ^= z >> 31
        return z & 0xFFFFFFFFFFFFFFFF

    def next32(self):
        return self.next64() & 0xFFFFFFFF

def apply_transposition(data, rows, cols, key16):
    prng = KeyedPRNG(key16)
    arr = np.array(data, dtype=np.uint8).reshape(rows, cols)
    
    # simple shuffle rows for visualization
    row_indices_map = list(range(rows)) # This will store the final mapping: original_idx -> final_idx
    
    # Fisher-Yates shuffle with PRNG
    shuffled_rows_order = list(range(rows)) # The actual order of rows in the output
    prng_calls = [] # To store the sequence of PRNG calls and swaps
    
    for i in range(rows - 1, 0, -1):
        j = prng.next32() % (i + 1)
        shuffled_rows_order[i], shuffled_rows_order[j] = shuffled_rows_order[j], shuffled_rows_order[i]
        prng_calls.append((i, j)) # Record the swap
        
    final_arr = arr[shuffled_rows_order, :] # Apply the final permutation

    # Create a mapping from final position to original row index
    # final_pos[k] = original_row_index_that_ends_up_at_k
    final_to_original_map = shuffled_rows_order 

    # Create a mapping from original row index to final position index
    # original_to_final_map[original_idx] = final_pos_idx
    original_to_final_map = [0] * rows
    for i, original_idx in enumerate(shuffled_rows_order):
        original_to_final_map[original_idx] = i

    return final_arr, original_to_final_map, prng_calls

# Prepare data
rows, cols = 8, 8
original_data = np.arange(rows * cols, dtype=np.uint8)
key16 = bytes(range(16))

# Run transposition
final_shuffled_arr, original_to_final_map, prng_calls = apply_transposition(original_data, rows, cols, key16)

# Animation setup
fig, axes = plt.subplots(1, 2, figsize=(10, 5))
ax_orig, ax_perm = axes

# Left: original grid
ax_orig.set_title("Original Data Grid")
orig_grid = original_data.reshape(rows, cols)
orig_img = ax_orig.imshow(orig_grid, cmap='viridis', vmin=0, vmax=255)
ax_orig.set_xticks(np.arange(-.5, cols, 1), minor=True)
ax_orig.set_yticks(np.arange(-.5, rows, 1), minor=True)
ax_orig.grid(which="minor", color="black", linestyle='-', linewidth=1)
ax_orig.set_xticks([])
ax_orig.set_yticks([])

# Right: permuted grid
ax_perm.set_title("Permuted Data Grid (Building)")
perm_img_data = np.full((rows, cols), -1, dtype=np.int16) # Use -1 for empty cells
perm_img = ax_perm.imshow(perm_img_data, cmap='viridis', vmin=0, vmax=255)
ax_perm.set_xticks(np.arange(-.5, cols, 1), minor=True)
ax_perm.set_yticks(np.arange(-.5, rows, 1), minor=True)
ax_perm.grid(which="minor", color="black", linestyle='-', linewidth=1)
ax_perm.set_xticks([])
ax_perm.set_yticks([])

# Text to show current operation
prng_text = ax_perm.text(0.02, 0.98, '', transform=ax_perm.transAxes, 
                          fontsize=10, verticalalignment='top', bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.5))


def init():
    perm_img.set_data(np.full((rows, cols), -1, dtype=np.int16))
    prng_text.set_text('')
    return [perm_img, prng_text]

def update(frame):
    current_perm_data = np.full((rows, cols), -1, dtype=np.int16)

    # Reconstruct the shuffled_rows_order step by step
    temp_shuffled_order = list(range(rows))
    for step in range(frame):
        if step < len(prng_calls):
            i, j = prng_calls[step]
            temp_shuffled_order[i], temp_shuffled_order[j] = temp_shuffled_order[j], temp_shuffled_order[i]
            
            # Highlight the rows being swapped in the original view (optional, can get busy)
            # For now, let's just focus on building the permuted grid

    # Based on the current temp_shuffled_order, populate the permuted data
    for final_pos_idx, original_row_idx in enumerate(temp_shuffled_order):
        current_perm_data[final_pos_idx, :] = orig_grid[original_row_idx, :]
    
    perm_img.set_data(current_perm_data)

    if frame < len(prng_calls):
        i, j = prng_calls[frame]
        prng_text.set_text(f"PRNG Swapped: Row {i} and {j}")
    elif frame == len(prng_calls):
        prng_text.set_text("Final Permutation")
    else:
        prng_text.set_text("") # Clear text after final frame

    return [perm_img, prng_text]

ani = animation.FuncAnimation(fig, update, frames=len(prng_calls) + 5, init_func=init,
                               blit=True, interval=500, repeat=False)

plt.tight_layout()
plt.show()

# To save the animation (requires ffmpeg or imagemagick)
ani.save('chaotic_transposition_animation.gif', writer='pillow', fps=2)
# ani.save('chaotic_transposition_animation.mp4', writer='ffmpeg', fps=2)