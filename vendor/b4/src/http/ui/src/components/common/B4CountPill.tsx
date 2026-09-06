import { Box } from "@mui/material";
import { colors, fonts } from "@design";

interface B4CountPillProps {
  value: string | number;
  sx?: object;
}

export const B4CountPill = ({ value, sx }: B4CountPillProps) => (
  <Box
    component="span"
    sx={{
      display: "inline-flex",
      alignItems: "center",
      height: 18,
      px: "7px",
      borderRadius: "9px",
      backgroundColor: colors.secondary,
      color: colors.text.tertiary,
      fontFamily: fonts.mono,
      fontSize: 11,
      fontWeight: 700,
      ...sx,
    }}
  >
    {value}
  </Box>
);
