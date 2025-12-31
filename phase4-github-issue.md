# Phase 4: Implement Professional Fusion Dark Mode Design System

## Overview
Implement the Professional Fusion Dark Mode design system as the default theme for PCM-Ops Tools, with light mode as an optional toggle. This phase focuses on creating a sophisticated, government-appropriate interface that balances Texas DIR professionalism with Rackspace Technology branding.

## Design Decision
After reviewing three mockup designs, the **Professional Fusion Dark Mode** has been selected as the preferred approach:
- **Government-first approach** with Texas DIR navy blue as primary color
- **Dark theme optimized** for extended professional use
- **Rackspace accents** strategically placed for brand recognition
- **Professional styling** appropriate for government operations

## Design Files
- ✅ `mockup_professional_fusion.html` - Original light mode design
- ✅ `mockup_professional_fusion_dark.html` - **Selected dark mode design (default)**
- ✅ `mockup_balanced_partnership.html` - Alternative balanced approach
- ✅ `mockup_rackspace_forward.html` - Alternative tech-forward approach

## Implementation Tasks

### 4.1 Theme System Foundation
- [ ] Create unified CSS variable system for light/dark themes
- [ ] Implement theme switching infrastructure
- [ ] Add localStorage persistence for user preferences
- [ ] Create theme toggle component

### 4.2 Core Template Updates
- [ ] Update `backend/templates/base.html` with Professional Fusion Dark design
- [ ] Implement responsive navigation with new styling
- [ ] Add theme switcher to main navigation
- [ ] Update footer with partnership branding

### 4.3 Tool Page Styling
- [ ] Apply new design to AWS tools pages:
  - [ ] Linux QC Patching Prep (`linux_qc_patching_prep.html`)
  - [ ] Linux QC Patching Post (`linux_qc_patching_post.html`) 
  - [ ] SFT Fixer (`sft_fixer.html`)
- [ ] Update home page (`index.html`) with new design
- [ ] Style authentication pages with consistent theme

### 4.4 Component Library
- [ ] Implement Professional Fusion button variants
- [ ] Create status dashboard components
- [ ] Design tool card components with hover effects
- [ ] Implement color palette and design tokens

### 4.5 Interactive Elements
- [ ] Add smooth theme transition animations
- [ ] Implement hover effects and micro-interactions
- [ ] Create loading states and feedback components
- [ ] Add subtle breathing animations for status indicators

## Design Specifications

### Color Palette (Dark Mode Default)
```css
/* Texas DIR Primary Colors - Dark Adapted */
--tx-navy: #004080;
--tx-light-blue: #0066cc;
--tx-navy-light: #1a4b7a;

/* Rackspace Accent Colors */
--rs-teal: #5bc0de;
--rs-teal-bright: #7dd3f0;
--rs-purple: #8b4789;
--rs-red: #c9302c;

/* Dark Theme Backgrounds */
--bg-primary: #1a1d23;
--bg-secondary: #252832;
--bg-card: #2d3139;
--bg-elevated: #363a44;

/* Dark Theme Text */
--text-primary: #ffffff;
--text-secondary: #b8bcc8;
--text-muted: #9ca3af;
```

### Design Philosophy
- **Government-First Dark**: Texas DIR navy blue as primary while optimized for dark theme readability
- **Enhanced Rackspace Accents**: Brighter teal variants for better contrast against dark backgrounds
- **Professional Dark UI**: Sophisticated color scheme with improved contrast ratios for accessibility
- **Elevated Elements**: Layered backgrounds and subtle shadows create depth and visual hierarchy
- **Dual Branding Harmony**: Partnership representation optimized for dark mode viewing

## Acceptance Criteria
- [ ] Professional Fusion Dark Mode implemented as default theme
- [ ] Light mode available via toggle switch
- [ ] Theme preference persisted across sessions
- [ ] All existing functionality preserved with new styling
- [ ] Responsive design works across all device sizes
- [ ] Accessibility standards maintained (WCAG 2.1 AA)
- [ ] Partnership branding appropriately represented
- [ ] Smooth animations and transitions implemented

## Technical Requirements
- CSS custom properties for theme variables
- JavaScript for theme switching logic
- localStorage for preference persistence
- Bootstrap 5 integration maintained
- Existing Jinja2 template structure preserved

## Dependencies
- Completion of Phase 3 (Configuration & Infrastructure)
- Current branch: `phase4-design-mockups`
- Base templates in `backend/templates/`
- Static assets in `backend/static/`

## Success Metrics
- Visual consistency across all application pages
- Improved user experience with dark mode default
- Professional appearance suitable for government clients
- Clear Rackspace Technology and Texas DIR partnership branding
- Accessibility compliance maintained
- Theme switching functionality working smoothly

## Related Files
- Design mockups: `mockup_professional_fusion*.html`
- Templates: `backend/templates/*.html`
- Static CSS: `backend/static/css/`
- Static JS: `backend/static/js/`

---
**Priority**: High  
**Estimated Effort**: 2-3 days  
**Labels**: enhancement, ui/ux, phase4, design-system