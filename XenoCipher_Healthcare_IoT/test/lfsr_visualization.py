import collections
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import random # For simulating chaotic taps initially

class SimpleLFSR:
    def __init__(self, seed, taps_mask, num_bits=16):
        self.state = seed & ((1 << num_bits) - 1)
        if self.state == 0:
            self.state = 1 # LFSR cannot start with all zeros
        self.taps = taps_mask
        self.num_bits = num_bits
        self.output_bits = collections.deque(maxlen=50) # To store recent output

    def step_bit(self):
        output_bit = self.state & 1 # LSB is output

        # Calculate feedback bit (parity of tapped bits)
        tapped_value = self.state & self.taps
        feedback_bit = 0
        while tapped_value > 0:
            feedback_bit ^= (tapped_value & 1)
            tapped_value >>= 1

        self.state = (self.state >> 1) | (feedback_bit << (self.num_bits - 1))
        self.output_bits.append(output_bit)
        return output_bit

    def get_bit_array(self):
        # Returns state as a list of bits, MSB first
        return [(self.state >> i) & 1 for i in range(self.num_bits - 1, -1, -1)]

    def get_taps_array(self):
        # Returns taps as a list of booleans, indicating which bits are tapped
        return [(self.taps >> i) & 1 for i in range(self.num_bits - 1, -1, -1)]

# --- Visualization Setup ---
NUM_BITS = 16
initial_seed = 0xACE1
initial_taps = 0x0029 # From your LFSR16 example

lfsr = SimpleLFSR(initial_seed, initial_taps, NUM_BITS)

fig, (ax_state, ax_output) = plt.subplots(2, 1, figsize=(10, 6), gridspec_kw={'height_ratios': [3, 1]})
fig.suptitle('LFSR Visualization')

# State visualization
state_bars = ax_state.bar(range(NUM_BITS), lfsr.get_bit_array(), color='skyblue')
tap_markers = ax_state.scatter([], [], color='red', marker='x', s=100, zorder=5, label='Tap points')
feedback_arrow = ax_state.annotate('', xy=(NUM_BITS - 0.5, 1.5), xytext=(-0.5, 1.5),
                                    arrowprops=dict(facecolor='green', shrink=0.05, width=2, headwidth=8))
output_arrow = ax_state.annotate('', xy=(-0.5, -0.5), xytext=(-0.5, 0.5),
                                  arrowprops=dict(facecolor='purple', shrink=0.05, width=2, headwidth=8))
ax_state.set_ylim(-0.2, 2.0)
ax_state.set_xticks(range(NUM_BITS))
ax_state.set_xticklabels([f'Bit {i}' for i in range(NUM_BITS - 1, -1, -1)])
ax_state.set_yticks([])
ax_state.set_title('LFSR State (MSB on left)')
ax_state.legend()

# Output visualization
output_line, = ax_output.plot([], [], 'o-')
ax_output.set_xlim(0, lfsr.output_bits.maxlen)
ax_output.set_ylim(-0.1, 1.1)
ax_output.set_title('Generated Output Bits')
ax_output.set_xlabel('Time Step')
ax_output.set_ylabel('Bit Value')

def animate(i):
    lfsr.step_bit()
    current_state_bits = lfsr.get_bit_array()
    current_taps_array = lfsr.get_taps_array()

    # Update state bars
    for j, bar in enumerate(state_bars):
        bar.set_height(current_state_bits[j])
        bar.set_color('blue' if current_state_bits[j] == 1 else 'skyblue')

    # Update tap markers
    tap_x = [j for j, tap_on in enumerate(current_taps_array) if tap_on]
    tap_y = [current_state_bits[j] for j in tap_x] # Place markers on top of the bits
    tap_markers.set_offsets(list(zip(tap_x, tap_y)))

    # Update output line
    output_line.set_data(range(len(lfsr.output_bits)), list(lfsr.output_bits))
    ax_output.set_xlim(max(0, len(lfsr.output_bits) - lfsr.output_bits.maxlen), len(lfsr.output_bits))

    # Return all artists that need to be redrawn
    return list(state_bars) + [tap_markers, output_line]

ani = animation.FuncAnimation(fig, animate, frames=200, interval=200, blit=True)
plt.tight_layout(rect=[0, 0, 1, 0.95]) # Adjust layout to prevent suptitle overlap
plt.show()