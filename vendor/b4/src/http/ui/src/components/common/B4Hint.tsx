import { ReactNode } from "react";
import { Box, Typography, SxProps, Theme, Grid } from "@mui/material";
import { InfoIcon } from "@b4.icons";
import { colors } from "@design";

interface B4HintProps {
  children: ReactNode;
  icon?: ReactNode;
  sx?: SxProps<Theme>;
}

export const B4Hint = ({ children, icon, sx }: B4HintProps) => (
  <Grid size={{ xs: 12 }}>
    <Box
      sx={{
        display: "flex",
        alignItems: "flex-start",
        gap: 1,
        ...sx,
      }}
    >
      <Box
        sx={{
          color: colors.text.primary,
          opacity: 0.7,
          display: "flex",
          alignItems: "center",
          mt: "2px",
          "& svg": { fontSize: "1rem" },
        }}
      >
        {icon ?? <InfoIcon fontSize="inherit" />}
      </Box>
      <Typography
        variant="body2"
        sx={{
          color: colors.text.primary,
          lineHeight: 1.55,
          flex: 1,
        }}
      >
        {children}
      </Typography>
    </Box>
  </Grid>
);
