import { forwardRef } from "react";
import { Grid, Alert, AlertProps } from "@mui/material";

interface B4AlertProps extends Omit<AlertProps, "severity"> {
  children: React.ReactNode;
  severity?: AlertProps["severity"];
  noWrapper?: boolean; // for Snackbar usage
}

export const B4Alert = forwardRef<HTMLDivElement, B4AlertProps>(
  ({ children, severity = "info", noWrapper = false, ...props }, ref) => {
    const alert = (
      <Alert ref={ref} severity={severity} {...props}>
        {children}
      </Alert>
    );

    if (noWrapper) {
      return alert;
    }

    return (
      <Grid size={{ xs: 12 }} sx={{ ...props.sx }}>
        {alert}
      </Grid>
    );
  }
);

B4Alert.displayName = "B4Alert";
