"""Quick proxmox-node1 RAM breakdown using range_manager registry."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.range_manager import RangeManagerAgent

reg = RangeManagerAgent.get_registry()
if not reg:
    print("No registry data. Run range_manager first.")
    sys.exit(1)

node = [n for n in reg["nodes"] if n["node"] == "proxmox-node1"][0]
guests = sorted(
    [g for g in reg["guests"] if g["node"] == "proxmox-node1"],
    key=lambda g: g["ram_used_gb"],
    reverse=True,
)

print("=== PVE1 RAM Breakdown ===")
print("Node Total: %.1fG" % node["ram_total_gb"])
print("Node Used:  %.1fG (%.1f%%)" % (node["ram_used_gb"], node["ram_pct"]))
print()

guest_total = sum(g["ram_used_gb"] for g in guests)
guest_alloc = sum(g["ram_total_gb"] for g in guests)

header = "%-20s %7s %7s %6s %8s" % ("Guest", "Used", "Alloc", "Use%", "of Node")
print(header)
print("-" * len(header))
for g in guests:
    use_pct = round(g["ram_used_gb"] * 100 / g["ram_total_gb"], 1) if g["ram_total_gb"] > 0 else 0
    node_pct = round(g["ram_used_gb"] * 100 / node["ram_total_gb"], 1)
    print(
        "%-20s %6.1fG %6.1fG %5.1f%% %6.1f%%"
        % (g["name"], g["ram_used_gb"], g["ram_total_gb"], use_pct, node_pct)
    )

print("-" * len(header))
print("%-20s %6.1fG %6.1fG" % ("Guest subtotal", guest_total, guest_alloc))
overhead = node["ram_used_gb"] - guest_total
print("%-20s %6.1fG" % ("PVE overhead/cache", overhead))
print("%-20s %6.1fG" % ("Free", node["ram_total_gb"] - node["ram_used_gb"]))
