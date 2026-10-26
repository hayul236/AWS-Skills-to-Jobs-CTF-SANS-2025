# Parse $GPGGA NMEA sentences (exported from a PCAP) into lat/lon CSV.
import re
import csv
import sys

PATTERN = re.compile(r"\$GPGGA,[^$]+")


def nmea_to_decimal(coord, hemi):
    if not coord or coord == "0":
        return None
    deg_len = 2 if hemi in "NS" else 3
    deg = float(coord[:deg_len])
    mins = float(coord[deg_len:])
    dec = deg + mins / 60
    return -dec if hemi in "SW" else dec


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "gps_raw.txt"
    out = sys.argv[2] if len(sys.argv) > 2 else "trail_trace.csv"

    rows = []
    for line in open(src):
        for sentence in PATTERN.findall(line):
            parts = sentence.split(",")
            if len(parts) > 5:
                lat = nmea_to_decimal(parts[2], parts[3])
                lon = nmea_to_decimal(parts[4], parts[5])
                if lat and lon:
                    rows.append([lat, lon])

    with open(out, "w", newline="") as f:
        csv.writer(f).writerows([["lat", "lon"], *rows])

    print(f"Extracted {len(rows)} coordinates -> {out}")
