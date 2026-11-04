package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.Card;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.SwingWorker;

/** A page of the application: a title, a card with the form and a result area. */
abstract class View extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final int CONTENT_WIDTH = 720;

    final ResultCard result = new ResultCard();
    final GuiActions actions;

    private final JPanel form = new JPanel();
    private final JPanel column = new JPanel();

    View(GuiActions actions, String title, String subtitle) {
        super(new BorderLayout());
        this.actions = actions;

        column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
        column.setOpaque(false);
        column.add(Widgets.label(title, Theme.bold(26f), Theme.TEXT));
        column.add(Box.createVerticalStrut(6));
        column.add(Widgets.label(subtitle, Theme.regular(14f), Theme.MUTED));
        column.add(Box.createVerticalStrut(22));

        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setOpaque(false);
        Card card = new Card(new BorderLayout());
        card.setBorder(BorderFactory.createEmptyBorder(22, 24, 8, 24));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(form, BorderLayout.CENTER);
        column.add(card);
        column.add(Box.createVerticalStrut(16));
        column.add(result);

        // Keeps the column at a comfortable width, centered, however large the window is
        JPanel centered = new JPanel(new GridBagLayout()) {
            private static final long serialVersionUID = 1L;

            @Override
            public Dimension getPreferredSize() {
                Dimension size = super.getPreferredSize();
                return new Dimension(Math.min(size.width, CONTENT_WIDTH + 80), size.height);
            }
        };
        centered.setOpaque(false);
        centered.setBorder(BorderFactory.createEmptyBorder(34, 40, 34, 40));
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTH;
        c.weightx = 1;
        c.weighty = 1;
        column.setMaximumSize(new Dimension(CONTENT_WIDTH, Integer.MAX_VALUE));
        centered.add(column, c);

        JScrollPane scroll = new JScrollPane(centered);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setOpaque(false);
        scroll.setOpaque(false);
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
    }

    /** Adds a row to the form, with the standard gap after it. */
    final void row(JComponent component) {
        component.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(component);
        form.add(Box.createVerticalStrut(16));
    }

    static JPasswordField passwordField() {
        JPasswordField field = new JPasswordField();
        field.setFont(Theme.regular(14f));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        return field;
    }

    /**
     * Runs an operation off the interface thread, which stays responsive during the
     * slow key derivation. Expected failures appear as caution results; anything else
     * appears as an error, and never as success.
     */
    final <T> void run(PrimaryButton button, Callable<T> operation, Consumer<T> onSuccess) {
        String label = button.getText();
        button.setEnabled(false);
        button.setText("Working…");
        result.hideResult();
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return operation.call();
            }

            @Override
            protected void done() {
                button.setText(label);
                button.setEnabled(true);
                try {
                    onSuccess.accept(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof GuiActions.ActionFailure) {
                        result.show(Tone.CAUTION, "Could not complete the operation",
                                List.of(cause.getMessage()), null, null);
                    } else {
                        result.show(Tone.DANGER, "Unexpected error", List.of(String.valueOf(cause)), null, null);
                    }
                }
            }
        }.execute();
    }
}
