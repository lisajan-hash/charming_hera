# Charming Hera - Findings Viewer

A beautiful web-based visualizer for SBOM security findings exported from Charming Hera.

## Features

🎨 **Beautiful Interface**: Modern, responsive design with gradients and animations  
📊 **Interactive Dashboard**: Overview statistics and package status at a glance  
🔍 **Search & Filter**: Real-time search through packages and findings  
📱 **Mobile Responsive**: Works perfectly on desktop, tablet, and mobile  
🎯 **Detailed Analysis**: Expandable package cards with finding details  
🏷️ **Color-coded Status**: Visual indicators for flagged, clean, and error states  

## How to Use

### 1. Export Data from Charming Hera
```bash
# Export all findings
python export_findings.py --output my_findings.json

# Export specific package findings  
python export_findings.py --package requests --output requests_findings.json
```

### 2. Open the Viewer
- Open `viewer/index.html` in any modern web browser
- Click "Select JSON File" and choose your exported JSON file
- Explore the interactive dashboard

### 3. Navigate the Interface

#### 📊 **Dashboard Overview**
- **Packages**: Total number of scanned packages
- **Total Findings**: Sum of all security findings
- **Flagged**: Packages with security issues
- **Clean**: Packages with no issues

#### 🔍 **Search & Explore**
- Use the search box to filter packages by name, ecosystem, or finding content
- Click on package headers to expand/collapse detailed findings
- Hover over elements for interactive effects

#### 📋 **Package Details**
- **Status Indicators**: Color-coded status (🚨 Flagged, ✅ Clean, ❌ Error)
- **Finding Categories**: Breakdown by detection type (network, execution, etc.)
- **Content Preview**: Actual code snippets where issues were found
- **File Paths**: Location of findings within packages

## Browser Compatibility

✅ **Chrome** 60+  
✅ **Firefox** 55+  
✅ **Safari** 12+  
✅ **Edge** 79+  

## Example Workflow

```bash
# 1. Scan packages with Charming Hera
python sbom_scanner.py --sbom my_sbom.json --show-results

# 2. Export findings for visualization  
python export_findings.py --output findings_report.json

# 3. Open viewer in browser
start viewer/index.html  # Windows
open viewer/index.html   # macOS  
xdg-open viewer/index.html  # Linux
```

## Features Showcase

### 🎨 Visual Design
- **Gradient backgrounds** for modern appeal
- **Card-based layout** for organized information
- **Smooth animations** and hover effects
- **Professional color scheme** with status indicators

### 📊 Data Visualization
- **Summary statistics** with large, readable numbers
- **Categorized findings** grouped by detection type
- **Expandable content** to manage information density
- **Real-time search** with instant filtering

### 🔍 Security Analysis
- **Finding details** with exact code snippets
- **File location** tracking for each finding
- **Severity indication** through color coding
- **Content preview** for quick assessment

## Tips

💡 **Performance**: Large JSON files (>1000 findings) may take a moment to load  
💡 **Search**: Use specific terms like "eval", "network", or package names for targeted results  
💡 **Navigation**: Collapse packages you've reviewed to focus on remaining items  
💡 **Mobile**: Swipe gestures work for expanding/collapsing on touch devices  

## Technical Details

- **Pure HTML/CSS/JavaScript**: No external dependencies
- **Client-side processing**: All data remains in your browser
- **Responsive design**: CSS Grid and Flexbox for all screen sizes
- **JSON parsing**: Robust error handling for malformed data