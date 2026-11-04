package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.gui.Widgets.GhostButton;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.datatransfer.DataFlavor;
import java.io.File;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.TransferHandler;

/** A path field with a Browse button, which also accepts a file dropped on it. */
final class FilePicker extends JPanel {
    private static final long serialVersionUID = 1L;

    private final JTextField path = new JTextField();

    FilePicker(String placeholder, boolean saving) {
        super(new BorderLayout(8, 0));
        setOpaque(false);
        path.putClientProperty("JTextField.placeholderText", placeholder);
        path.setFont(Theme.regular(13.5f));
        path.setTransferHandler(new DropHandler());
        GhostButton browse = new GhostButton(t("common.browse"));
        browse.addActionListener(event -> choose(saving));
        add(path, BorderLayout.CENTER);
        add(browse, BorderLayout.EAST);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
    }

    String value() {
        return path.getText();
    }

    void value(String value) {
        path.setText(value);
    }

    /** Runs when the path changes, by typing, browsing or dropping. */
    void onChange(Runnable listener) {
        path.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                listener.run();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                listener.run();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                listener.run();
            }
        });
    }

    private void choose(boolean saving) {
        JFileChooser chooser = new JFileChooser();
        if (!path.getText().isBlank()) {
            chooser.setSelectedFile(new File(path.getText().strip()));
        }
        int answer = saving ? chooser.showSaveDialog(this) : chooser.showOpenDialog(this);
        if (answer == JFileChooser.APPROVE_OPTION) {
            path.setText(chooser.getSelectedFile().getPath());
        }
    }

    private final class DropHandler extends TransferHandler {
        private static final long serialVersionUID = 1L;

        @Override
        public boolean canImport(TransferSupport support) {
            return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)
                    || support.isDataFlavorSupported(DataFlavor.stringFlavor);
        }

        @Override
        public boolean importData(TransferSupport support) {
            try {
                if (support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                    @SuppressWarnings("unchecked")
                    List<File> files = (List<File>) support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    path.setText(files.get(0).getPath());
                } else {
                    path.replaceSelection((String) support.getTransferable().getTransferData(DataFlavor.stringFlavor));
                }
                return true;
            } catch (java.awt.datatransfer.UnsupportedFlavorException | java.io.IOException e) {
                return false;
            }
        }
    }
}
