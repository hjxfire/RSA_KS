package RSA_KS;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JComboBox;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.awt.event.ActionEvent;

public class RSAWindow extends JFrame {

	private JPanel contentPane;
	protected JTextField JTFP;
	protected JTextField JTFQ;
	protected JTextField JTFN;
	protected JTextField JTFE;
	protected JTextField JTFD;
	protected JTextArea JTAC;
	protected JTextArea JTAM;
	protected JRadioButton JRBAuto;
	protected JRadioButton JRBHM;
	protected static RSA rsa;
	private final ButtonGroup buttonGroup = new ButtonGroup();

	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					RSAWindow frame = new RSAWindow();
					frame.setVisible(true);
					rsa=new RSA(frame);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public RSAWindow() throws ClassNotFoundException, InstantiationException, IllegalAccessException, UnsupportedLookAndFeelException {
		setTitle("RSA_KS");
		UIManager.setLookAndFeel("com.sun.java.swing.plaf.nimbus.NimbusLookAndFeel");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 733, 588);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		JRadioButton JRBAuto = new JRadioButton("自动生成n,e,d");
		buttonGroup.add(JRBAuto);
		JRBAuto.setSelected(true);
		
		JRadioButton JRBHM = new JRadioButton("手动输入n,e,d");
		buttonGroup.add(JRBHM);
		
		JComboBox JCBKeyLength = new JComboBox();
		JCBKeyLength.addItem(1024);
		JCBKeyLength.addItem(2048);
		
		JLabel JLKeyLength = new JLabel("密钥n长度:");
		
		JLabel JLP = new JLabel("p:");
		
		JButton JBProducePQ = new JButton("生成p,q,n");
		JBProducePQ.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				rsa.producePQN((int)JCBKeyLength.getSelectedItem());
			}
		});
		
		JTFP = new JTextField();
		JTFP.setEditable(false);
		JTFP.setColumns(10);
		
		JLabel JLQ = new JLabel("q:");
		
		JTFQ = new JTextField();
		JTFQ.setEditable(false);
		JTFQ.setColumns(10);
		
		JLabel JLN = new JLabel("n:");
		
		JTFN = new JTextField();
		JTFN.setColumns(10);
		
		JButton JBProduceED = new JButton("生成e,d");
		JBProduceED.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				rsa.produceED();
			}
		});
		
		JLabel JLBE = new JLabel("e:");
		
		JLabel JLD = new JLabel("d:");
		
		JTFE = new JTextField();
		JTFE.setColumns(10);
		
		JTFD = new JTextField();
		JTFD.setColumns(10);
		
		JLabel JLM = new JLabel("明文:");
		
		JTAM = new JTextArea();
		JTAM.setLineWrap(true);
		
		JLabel JLC = new JLabel("密文:");
		
		JTAC = new JTextArea();
		JTAC.setLineWrap(true);
		
		JButton JBEn = new JButton("加密");
		JBEn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(JRBAuto.isSelected())
				{
					//内部n,e加密
					try {
						rsa.enDivide(JTAM.getText(), rsa.getN(), rsa.getE(),(int)JCBKeyLength.getSelectedItem());
					} catch (UnsupportedEncodingException e1) {
						e1.printStackTrace();
					}
				}
				else
				{
					//外部输入n,e加密
					try {
						rsa.enDivide(JTAM.getText(), new BigInteger(JTFN.getText(),16), new BigInteger(JTFE.getText(),16),(int)JCBKeyLength.getSelectedItem());
					} catch (UnsupportedEncodingException e1) {
						e1.printStackTrace();
					}
				}
			}
		});
		buttonGroup.add(JBEn);
		
		JButton JBDe = new JButton("解密");
		JBDe.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(JRBAuto.isSelected())
				{
					//内部n,d解密
					try {
						rsa.deDivide(JTAC.getText(), rsa.getN(), rsa.getD(),(int)JCBKeyLength.getSelectedItem());
					} catch (UnsupportedEncodingException e1) {
						e1.printStackTrace();
					}
				}
				else
				{
					//外部输入n,d解密
					try {
						rsa.deDivide(JTAC.getText(), new BigInteger(JTFN.getText(),16), new BigInteger(JTFD.getText(),16),(int)JCBKeyLength.getSelectedItem());
					} catch (UnsupportedEncodingException e1) {
						e1.printStackTrace();
					}
				}
			}
		});
		buttonGroup.add(JBDe);
		
		JLabel lblNewLabel = new JLabel("(p,q,n,e,d,密文均以16进制显示)");
		lblNewLabel.setForeground(new Color(153, 0, 0));
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.TRAILING)
						.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
							.addContainerGap()
							.addComponent(JTAC, GroupLayout.DEFAULT_SIZE, 695, Short.MAX_VALUE))
						.addGroup(gl_contentPane.createParallelGroup(Alignment.TRAILING)
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addContainerGap()
								.addComponent(JTAM, GroupLayout.DEFAULT_SIZE, 695, Short.MAX_VALUE))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLN, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JTFN, GroupLayout.DEFAULT_SIZE, 685, Short.MAX_VALUE))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLQ)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JTFQ, GroupLayout.DEFAULT_SIZE, 685, Short.MAX_VALUE))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLP)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JTFP, GroupLayout.DEFAULT_SIZE, 685, Short.MAX_VALUE))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLBE)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JTFE, GroupLayout.DEFAULT_SIZE, 685, Short.MAX_VALUE))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLD)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JTFD, GroupLayout.DEFAULT_SIZE, 685, Short.MAX_VALUE))
							.addComponent(JLM, Alignment.LEADING)
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JRBAuto)
								.addGap(18)
								.addComponent(JRBHM))
							.addGroup(Alignment.LEADING, gl_contentPane.createSequentialGroup()
								.addComponent(JLKeyLength)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JCBKeyLength, GroupLayout.PREFERRED_SIZE, 66, GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JBProducePQ)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JBProduceED)
								.addGap(37)
								.addComponent(JBEn)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(JBDe)
								.addPreferredGap(ComponentPlacement.RELATED, 96, Short.MAX_VALUE)
								.addComponent(lblNewLabel)))
						.addComponent(JLC, Alignment.LEADING))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JRBAuto)
						.addComponent(JRBHM))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGap(10)
							.addComponent(JLKeyLength))
						.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
							.addComponent(JCBKeyLength, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addComponent(JBProducePQ)
							.addComponent(JBProduceED)
							.addComponent(JBEn)
							.addComponent(JBDe)
							.addComponent(lblNewLabel)))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JLP)
						.addComponent(JTFP, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JLQ)
						.addComponent(JTFQ, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JLN)
						.addComponent(JTFN, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JLBE)
						.addComponent(JTFE, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(JLD)
						.addComponent(JTFD, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(JLM)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(JTAM, GroupLayout.PREFERRED_SIZE, 93, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(JLC)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(JTAC, GroupLayout.DEFAULT_SIZE, 134, Short.MAX_VALUE)
					.addContainerGap())
		);
		contentPane.setLayout(gl_contentPane);
	}
}
