# Translating

## New translations

To create a new translation for Lenspect:

1. Use a [PO file](https://www.gnu.org/software/gettext/manual/html_node/PO-Files.html) editor of your choice.
2. Create a new translation based on the [`lenspect.pot`](lenspect.pot) file.
3. Select the target language for the new translation.
4. Translate all strings in the editor.
5. Save the file as `<language_code>.po` in the `po` directory.
6. Add the language code to the [`LINGUAS`](LINGUAS) file.

## Updating translations

When new strings for translation appear in the source code:

1. Run the POT file [update script](update-pot.sh):
   ```
   ./po/update-pot.sh
   ```
2. Open the existing `.po` file in your editor.
3. Update the translation from the new POT file.
4. Translate new strings and review existing translations.
5. Save the updated `.po` file.

## Submitting changes

After creating a new translation or updating an existing one:

1. Ensure all changes are saved.
2. Create a new branch in your fork of the repository.
3. Commit the changes to the `.po` file and `LINGUAS`.
4. Push the changes to your fork on GitHub.
5. Create a pull request to the Lenspect repository.

Thank you for translating this project!
