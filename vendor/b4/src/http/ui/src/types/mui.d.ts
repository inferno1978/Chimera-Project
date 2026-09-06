import "@mui/material/Button";
import "@mui/material/Chip";
import "@mui/material/Tabs";

declare module "@mui/material/Button" {
  interface ButtonPropsVariantOverrides {
    "b4.link": true;
    "b4.primary": true;
    "b4.secondary": true;
    "b4.cancel": true;
  }
}

declare module "@mui/material/Chip" {
  interface ChipPropsVariantOverrides {
    "b4.chip": true;
  }
}

declare module "@mui/material/Tabs" {
  interface TabsPropsVariantOverrides {
    "b4.tabs": true;
  }
}

declare module "@mui/material/TextField" {
  interface TextFieldPropsVariantOverrides {
    "b4.field": true;
  }
}
