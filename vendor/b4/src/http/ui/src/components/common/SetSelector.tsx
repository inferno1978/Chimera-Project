import { useState } from "react";
import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Button,
} from "@mui/material";
import { AddIcon } from "@b4.icons";
import { B4TextField } from "@b4.fields";
import { colors } from "@design";
import { B4SetConfig, CREATE_SET_SENTINEL } from "@models/config";
import { useTranslation } from "react-i18next";

interface SetSelectorProps {
  sets: B4SetConfig[];
  value: string;
  onChange: (setId: string, newSetName?: string) => void;
  label?: string;
  disabled?: boolean;
}

export const SetSelector = ({
  sets,
  value,
  onChange,
  label,
  disabled = false,
}: SetSelectorProps) => {
  const { t } = useTranslation();
  const resolvedLabel = label ?? t("core.targetSet");
  const [isCreating, setIsCreating] = useState(false);
  const [newSetName, setNewSetName] = useState("");

  const handleCancelCreate = () => {
    setIsCreating(false);
    setNewSetName("");
  };

  if (isCreating) {
    return (
      <B4TextField
        label={t("core.setName")}
        value={newSetName}
        onChange={(e) => {
          setNewSetName(e.target.value);
          onChange(CREATE_SET_SENTINEL, e.target.value);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" && newSetName.trim()) {
            setIsCreating(false);
            setNewSetName("");
          } else if (e.key === "Escape") {
            handleCancelCreate();
          }
        }}
        autoFocus
        slotProps={{
          input: {
            endAdornment: (
              <Button
                size="small"
                onClick={() => {
                  const firstEnabled = sets.find((s) => s.enabled);
                  onChange(value || firstEnabled?.id || sets[0]?.id || "");
                  handleCancelCreate();
                }}
                sx={{ minWidth: "auto" }}
              >
                {t("core.cancel")}
              </Button>
            ),
          },
        }}
        sx={{
          "& .MuiInputBase-root": {
            bgcolor: colors.background.dark,
          },
          "& fieldset": {
            borderColor: `${colors.border.default} !important`,
          },
        }}
      />
    );
  }

  return (
    <FormControl fullWidth disabled={disabled}>
      <InputLabel>{resolvedLabel}</InputLabel>
      <Select
        value={value}
        label={resolvedLabel}
        onChange={(e) => {
          if (e.target.value === CREATE_SET_SENTINEL) {
            setIsCreating(true);
          } else {
            onChange(e.target.value);
          }
        }}
        sx={{
          bgcolor: colors.background.dark,
          "& fieldset": {
            borderColor: `${colors.border.default} !important`,
          },
        }}
      >
        <MenuItem
          value={CREATE_SET_SENTINEL}
          sx={{
            color: colors.primary,
            fontWeight: 600,
            borderBottom: `1px solid ${colors.border.default}`,
            "&:hover": {
              bgcolor: colors.accent.primary,
            },
          }}
        >
          <AddIcon sx={{ mr: 1, fontSize: 18 }} />
          {t("core.createNewSet")}
        </MenuItem>
        {sets
          .filter((set) => set.enabled)
          .map((set) => (
            <MenuItem key={set.id} value={set.id}>
              {set.name}
            </MenuItem>
          ))}
      </Select>
    </FormControl>
  );
};
