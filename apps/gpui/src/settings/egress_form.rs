/// The output list being edited and the output selected in the add picker.
/// Keeping them together prevents Save from losing a selected replacement.
pub(super) struct TargetDraft {
    targets: Vec<String>,
    pending: Option<String>,
}

impl TargetDraft {
    pub(super) fn new(targets: Vec<String>) -> Self {
        Self {
            targets,
            pending: None,
        }
    }

    pub(super) fn targets(&self) -> &[String] {
        &self.targets
    }

    pub(super) fn select(&mut self, kind: &str, value: &str) {
        self.pending = (!value.is_empty()).then(|| format!("{kind}:{value}"));
    }

    pub(super) fn remove(&mut self, target: &str) {
        self.targets.retain(|item| item != target);
        if self.pending.as_deref() == Some(target) {
            self.pending = None;
        }
    }

    pub(super) fn add(&mut self, kind: &str, value: &str) -> Result<(), &'static str> {
        self.select(kind, value);
        let target = self.pending.take().ok_or("Choose an output to add.")?;
        if !self.targets.contains(&target) {
            self.targets.push(target);
        }
        Ok(())
    }

    pub(super) fn targets_for_save(&self) -> Result<Vec<String>, &'static str> {
        let mut targets = self.targets.clone();
        if let Some(target) = &self.pending {
            if !targets.contains(target) {
                targets.push(target.clone());
            }
        }
        if targets.is_empty() {
            return Err("Choose at least one output before saving this egress.");
        }
        Ok(targets)
    }
}

#[cfg(test)]
mod tests {
    use super::TargetDraft;

    #[test]
    fn save_keeps_selected_replacement_after_removing_old_proxy() {
        let mut draft = TargetDraft::new(vec!["proxy:old".into()]);
        draft.remove("proxy:old");
        draft.select("proxy", "replacement");
        assert_eq!(draft.targets_for_save().unwrap(), vec!["proxy:replacement"]);
    }

    #[test]
    fn removing_last_output_cannot_silently_save_an_empty_egress() {
        let mut draft = TargetDraft::new(vec!["proxy:old".into()]);
        draft.remove("proxy:old");
        assert!(draft.targets_for_save().is_err());
    }

    #[test]
    fn add_then_save_does_not_duplicate_replacement() {
        let mut draft = TargetDraft::new(vec!["proxy:old".into()]);
        draft.remove("proxy:old");
        draft.select("proxy", "replacement");
        draft.add("proxy", "replacement").unwrap();
        assert_eq!(draft.targets(), &["proxy:replacement"]);
        assert_eq!(draft.targets_for_save().unwrap(), vec!["proxy:replacement"]);
    }

    #[test]
    fn unchanged_form_does_not_add_the_default_picker_option() {
        let draft = TargetDraft::new(vec!["proxy:old".into()]);
        assert_eq!(draft.targets_for_save().unwrap(), vec!["proxy:old"]);
    }

    #[test]
    fn removing_selected_output_does_not_add_it_back_on_save() {
        let mut draft = TargetDraft::new(vec!["proxy:old".into()]);
        draft.select("proxy", "old");
        draft.remove("proxy:old");
        assert!(draft.targets_for_save().is_err());
    }

    #[test]
    fn replacement_preserves_other_outputs_and_their_order() {
        let mut draft = TargetDraft::new(vec!["proxy:old".into(), "dev:eth0".into()]);
        draft.remove("proxy:old");
        draft.select("proxy", "replacement");
        assert_eq!(
            draft.targets_for_save().unwrap(),
            vec!["dev:eth0", "proxy:replacement"]
        );
    }
}
