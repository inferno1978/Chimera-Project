import { Box } from "@mui/material";
import { colors, fonts } from "@design";

type ConfidenceVariant = "default" | "high" | "low";

interface B4ConfidencePillProps {
  score: string | number;
  variant?: ConfidenceVariant;
  sx?: object;
}

const styles: Record<
  ConfidenceVariant,
  { bg: string; fg: string; border: string }
> = {
  default: {
    bg: colors.accent.secondary,
    fg: colors.secondary,
    border: "rgba(245, 173, 24, 0.4)",
  },
  high: {
    bg: colors.secondary,
    fg: colors.text.tertiary,
    border: colors.secondary,
  },
  low: {
    bg: colors.accent.secondaryHover,
    fg: "rgba(245, 173, 24, 0.6)",
    border: colors.accent.secondary,
  },
};

export const B4ConfidencePill = ({
  score,
  variant = "default",
  sx,
}: B4ConfidencePillProps) => {
  const s = styles[variant];
  return (
    <Box
      component="span"
      sx={{
        display: "inline-flex",
        alignItems: "center",
        height: 18,
        px: "8px",
        borderRadius: "9px",
        fontFamily: fonts.mono,
        fontSize: 11,
        fontWeight: 700,
        backgroundColor: s.bg,
        color: s.fg,
        border: `1px solid ${s.border}`,
        ...sx,
      }}
    >
      {score}
    </Box>
  );
};
