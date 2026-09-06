import { colors } from "@design";
import { Tooltip, IconButton } from "@mui/material";

interface B4TooltipButtonProps {
  title: string;
  onClick: (event: React.MouseEvent<HTMLButtonElement>) => void;
  icon: React.ReactNode;
}

export const B4TooltipButton = ({
  title,
  onClick,
  icon,
}: B4TooltipButtonProps) => {
  return (
    <Tooltip title={title}>
      <IconButton
        size="small"
        onClick={onClick}
        sx={{
          "&:hover": { color: colors.secondary },
        }}
      >
        {icon}
      </IconButton>
    </Tooltip>
  );
};
