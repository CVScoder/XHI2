import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.patches import Rectangle, FancyBboxPatch
import time
import random

class NTRUVisualization:
    def __init__(self):
        # NTRU parameters (simplified for visualization)
        self.N = 11  # Reduced from 251 for better visualization
        self.P = 3
        self.Q = 32  # Reduced from 128
        self.D = 4   # Reduced from 71
        
        # Setup the figure
        self.fig, self.axes = plt.subplots(2, 3, figsize=(18, 12))
        self.fig.suptitle('NTRU Cryptosystem Visualization', fontsize=16, fontweight='bold')
        
        # Initialize polynomials
        self.f = np.zeros(self.N, dtype=int)
        self.g = np.zeros(self.N, dtype=int)
        self.h = np.zeros(self.N, dtype=int)
        self.m = np.zeros(self.N, dtype=int)
        self.r = np.zeros(self.N, dtype=int)
        self.e = np.zeros(self.N, dtype=int)
        self.decrypted = np.zeros(self.N, dtype=int)
        
        self.setup_plots()
        
    def setup_plots(self):
        """Setup all subplot configurations"""
        titles = [
            'Private Key f (ternary)', 'Helper Polynomial g (ternary)', 'Public Key h = p*g*f⁻¹',
            'Message m', 'Random r (ternary)', 'Ciphertext e = r*h + m'
        ]
        
        colors = ['red', 'blue', 'green', 'purple', 'orange', 'brown']
        
        for i, (ax, title, color) in enumerate(zip(self.axes.flat, titles, colors)):
            ax.set_title(title, fontweight='bold', color=color)
            ax.set_xlabel('Coefficient Index')
            ax.set_ylabel('Value')
            ax.grid(True, alpha=0.3)
            ax.set_xlim(-0.5, self.N - 0.5)
            
            # Set appropriate y-limits for different polynomials
            if 'ternary' in title.lower():
                ax.set_ylim(-1.5, 1.5)
            elif 'message' in title.lower():
                ax.set_ylim(-0.5, self.P - 0.5)
            else:
                ax.set_ylim(-self.Q//2, self.Q//2)
        
        plt.tight_layout()
    
    def generate_ternary(self, d):
        """Generate a ternary polynomial with d coefficients of +1 and d coefficients of -1"""
        poly = np.zeros(self.N, dtype=int)
        positions = random.sample(range(self.N), 2 * d)
        
        # Set d positions to +1
        for i in range(d):
            poly[positions[i]] = 1
        
        # Set d positions to -1
        for i in range(d, 2 * d):
            poly[positions[i]] = -1
            
        return poly
    
    def poly_mult_mod(self, a, b, mod):
        """Polynomial multiplication in ring Z[x]/(x^N - 1) mod q"""
        result = np.zeros(self.N, dtype=int)
        for i in range(self.N):
            for j in range(self.N):
                idx = (i + j) % self.N
                result[idx] += a[i] * b[j]
        return result % mod
    
    def poly_inv_simple(self, f):
        """Simplified polynomial inverse (placeholder for visualization)"""
        # This is a simplified version - real NTRU uses extended Euclidean algorithm
        inv = np.zeros(self.N, dtype=int)
        inv[0] = 1  # Placeholder
        return inv
    
    def animate_polynomial(self, ax, poly, color, title):
        """Animate the creation of a polynomial"""
        ax.clear()
        ax.set_title(title, fontweight='bold', color=color)
        ax.set_xlabel('Coefficient Index')
        ax.set_ylabel('Value')
        ax.grid(True, alpha=0.3)
        ax.set_xlim(-0.5, self.N - 0.5)
        
        if 'ternary' in title.lower():
            ax.set_ylim(-1.5, 1.5)
        elif 'message' in title.lower():
            ax.set_ylim(-0.5, self.P - 0.5)
        else:
            ax.set_ylim(-self.Q//2, self.Q//2)
        
        # Animate coefficient by coefficient
        x_pos = range(self.N)
        bars = ax.bar(x_pos, poly, color=color, alpha=0.7, edgecolor='black')
        
        # Add value labels on bars
        for i, (bar, val) in enumerate(zip(bars, poly)):
            if val != 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1 * np.sign(val),
                       str(val), ha='center', va='bottom' if val > 0 else 'top', fontweight='bold')
        
        plt.draw()
        plt.pause(0.5)
    
    def run_visualization(self):
        """Run the complete NTRU visualization"""
        print("🔐 NTRU Cryptosystem Visualization")
        print("=" * 50)
        
        # Step 1: Key Generation
        print("\n📋 Step 1: Key Generation")
        print("-" * 30)
        
        # Generate private key f (ternary)
        print("Generating private key f (ternary polynomial)...")
        self.f = self.generate_ternary(self.D)
        self.animate_polynomial(self.axes[0,0], self.f, 'red', 'Private Key f (ternary)')
        
        # Generate helper polynomial g (ternary)
        print("Generating helper polynomial g (ternary)...")
        self.g = self.generate_ternary(self.D)
        self.animate_polynomial(self.axes[0,1], self.g, 'blue', 'Helper Polynomial g (ternary)')
        
        # Generate public key h = p * g * f^(-1) mod q
        print("Computing public key h = p * g * f⁻¹ mod q...")
        f_inv = self.poly_inv_simple(self.f)  # Simplified for visualization
        temp = self.poly_mult_mod(self.g, f_inv, self.Q)
        self.h = (self.P * temp) % self.Q
        self.animate_polynomial(self.axes[0,2], self.h, 'green', 'Public Key h = p*g*f⁻¹')
        
        # Step 2: Encryption
        print("\n🔒 Step 2: Encryption")
        print("-" * 25)
        
        # Generate message
        print("Creating message polynomial...")
        self.m = np.random.randint(0, self.P, self.N)
        self.animate_polynomial(self.axes[1,0], self.m, 'purple', 'Message m')
        
        # Generate random polynomial r
        print("Generating random polynomial r...")
        self.r = self.generate_ternary(self.D)
        self.animate_polynomial(self.axes[1,1], self.r, 'orange', 'Random r (ternary)')
        
        # Compute ciphertext e = r * h + m mod q
        print("Computing ciphertext e = r * h + m mod q...")
        rh = self.poly_mult_mod(self.r, self.h, self.Q)
        self.e = (rh + self.m) % self.Q
        self.animate_polynomial(self.axes[1,2], self.e, 'brown', 'Ciphertext e = r*h + m')
        
        # Step 3: Decryption
        print("\n🔓 Step 3: Decryption")
        print("-" * 25)
        
        # Decrypt: compute e * f mod q, then mod p
        print("Decrypting: computing e * f mod q, then mod p...")
        ef = self.poly_mult_mod(self.e, self.f, self.Q)
        self.decrypted = ef % self.P
        
        # Show decryption result
        self.show_decryption_result()
        
        # Show summary
        self.show_summary()
    
    def show_decryption_result(self):
        """Show the decryption result and comparison with original message"""
        fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        fig2.suptitle('Decryption Result', fontsize=14, fontweight='bold')
        
        x_pos = range(self.N)
        
        # Original message
        ax1.bar(x_pos, self.m, color='purple', alpha=0.7, edgecolor='black')
        ax1.set_title('Original Message', fontweight='bold', color='purple')
        ax1.set_xlabel('Coefficient Index')
        ax1.set_ylabel('Value')
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(-0.5, self.P - 0.5)
        
        # Decrypted message
        ax2.bar(x_pos, self.decrypted, color='green', alpha=0.7, edgecolor='black')
        ax2.set_title('Decrypted Message', fontweight='bold', color='green')
        ax2.set_xlabel('Coefficient Index')
        ax2.set_ylabel('Value')
        ax2.grid(True, alpha=0.3)
        ax2.set_ylim(-0.5, self.P - 0.5)
        
        # Add value labels
        for ax, poly in [(ax1, self.m), (ax2, self.decrypted)]:
            for i, val in enumerate(poly):
                if val != 0:
                    ax.text(i, val + 0.1, str(val), ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.show()
        
        # Check if decryption was successful
        success = np.array_equal(self.m, self.decrypted)
        print(f"Decryption {'✅ SUCCESSFUL' if success else '❌ FAILED'}")
    
    def show_summary(self):
        """Show a summary of the NTRU process"""
        fig3, ax = plt.subplots(figsize=(12, 8))
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 10)
        ax.axis('off')
        
        # Title
        ax.text(5, 9.5, 'NTRU Cryptosystem Summary', ha='center', va='center', 
                fontsize=18, fontweight='bold')
        
        # Key Generation
        key_gen_box = FancyBboxPatch((0.5, 7), 4, 1.5, boxstyle="round,pad=0.1", 
                                     facecolor='lightblue', edgecolor='blue', linewidth=2)
        ax.add_patch(key_gen_box)
        ax.text(2.5, 7.75, 'Key Generation', ha='center', va='center', 
                fontsize=12, fontweight='bold')
        ax.text(2.5, 7.25, f'f, g ∈ ternary polynomials\nh = p·g·f⁻¹ mod q', 
                ha='center', va='center', fontsize=10)
        
        # Encryption
        enc_box = FancyBboxPatch((5.5, 7), 4, 1.5, boxstyle="round,pad=0.1", 
                                 facecolor='lightcoral', edgecolor='red', linewidth=2)
        ax.add_patch(enc_box)
        ax.text(7.5, 7.75, 'Encryption', ha='center', va='center', 
                fontsize=12, fontweight='bold')
        ax.text(7.5, 7.25, f'r ∈ ternary polynomial\ne = r·h + m mod q', 
                ha='center', va='center', fontsize=10)
        
        # Decryption
        dec_box = FancyBboxPatch((3, 4.5), 4, 1.5, boxstyle="round,pad=0.1", 
                                 facecolor='lightgreen', edgecolor='green', linewidth=2)
        ax.add_patch(dec_box)
        ax.text(5, 5.25, 'Decryption', ha='center', va='center', 
                fontsize=12, fontweight='bold')
        ax.text(5, 4.75, f'a = e·f mod q\nm = a mod p', 
                ha='center', va='center', fontsize=10)
        
        # Parameters
        param_box = FancyBboxPatch((1, 1.5), 8, 2, boxstyle="round,pad=0.1", 
                                   facecolor='lightyellow', edgecolor='orange', linewidth=2)
        ax.add_patch(param_box)
        ax.text(5, 3, 'NTRU Parameters (Simplified for Visualization)', 
                ha='center', va='center', fontsize=12, fontweight='bold')
        ax.text(5, 2.2, f'N = {self.N} (polynomial degree)\n'
                        f'p = {self.P} (small modulus)\n'
                        f'q = {self.Q} (large modulus)\n'
                        f'd = {self.D} (number of ±1 coefficients)', 
                ha='center', va='center', fontsize=10)
        
        # Security note
        ax.text(5, 0.5, '🔒 Security based on lattice problems (SVP/CVP)', 
                ha='center', va='center', fontsize=11, fontweight='bold', color='darkred')
        
        plt.tight_layout()
        plt.show()

def main():
    """Main function to run the NTRU visualization"""
    print("🚀 Starting NTRU Cryptosystem Visualization...")
    print("This visualization demonstrates the core concepts of NTRU encryption.")
    print("Note: Parameters are simplified for better visual understanding.")
    
    # Create and run visualization
    ntru_viz = NTRUVisualization()
    
    try:
        ntru_viz.run_visualization()
        
        print("\n" + "="*50)
        print("📊 Visualization Complete!")
        print("Key Concepts Demonstrated:")
        print("• Ternary polynomials for keys and randomness")
        print("• Polynomial arithmetic in quotient rings")
        print("• Modular reduction for security")
        print("• Lattice-based cryptography principles")
        print("="*50)
        
        input("\nPress Enter to close all windows...")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Visualization interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during visualization: {e}")
    finally:
        plt.close('all')

if __name__ == "__main__":
    main()
