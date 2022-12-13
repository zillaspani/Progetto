package hadron.heuristic;

import hadron.board.Board;
import hadron.research.GameController;
import hadron.research.Node;


import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Random;

import javax.security.auth.PrivateCredentialPermission;

public class MyHeuristic implements Heuristic {
	private static class Cella{
		public Cella(int i,int j){
			this.i=i;
			this.j=j;
			occupata=false;
		}
		public int i;
		public int j;
		public boolean occupata;
	}
	private LinkedList<Cella> lCelle;
	private static boolean primaFase;
	private static boolean secondaFase;
	//private static int it=0;
	private int myCol;
	private static final long serialVersionUID = 5783084660998719046L;

	/**
	 * Costruttore euristica
	 */
	public MyHeuristic(){
		primaFase=true;
		secondaFase=true;
		lCelle=new LinkedList<>();
		lCelle.add(new Cella(1,1));
		lCelle.add(new Cella(1,4));
		lCelle.add(new Cella(1,7));
		lCelle.add(new Cella(4,1));
		lCelle.add(new Cella(4,7));
		lCelle.add(new Cella(7,1));
		lCelle.add(new Cella(7,4));
		lCelle.add(new Cella(7,7));
		lCelle.addFirst(new Cella(4,4));
	}
	@Override
	public double evaluate(Board b, int col) {
		if(col==0) myCol=1;
		else myCol=0;

		double valutazione=0;
		if(b.isFinal()) return -100000D; //centomila

		if(primaFase&&checkFirstPhase(b)){
			valutazione=firstPhase(b);
			if(valutazione==0) return 0;
			return valutazione;
		}
		if(secondaFase&&checkSecondPhase(b)){
			valutazione=secondPhase(b);
			return valutazione;
		}

		valutazione=lastPhase(b, myCol);
		return valutazione;
	}

	private double firstPhase(Board b) {
		int count=0;
		for(Cella c : lCelle){
			if(b.getCol(c.i,c.j)==myCol){
				if(c.i==4&&c.j==4) count++;
				count++;
			}
		}

		return count*-10000D;
	}
	//restituisce true se esiste una posizione ancora libera
	//restituisce false se non esiste una posizione ancora libera
	private boolean checkFirstPhase(Board b) {
		for(Cella c : lCelle){
			if(b.getCol(c.i,c.j)==-1){
				return true;
			}
		}
		primaFase=false;
		return false;
	}

	private double secondPhase(Board b){
		double total=0;
		for(int i=0;i<9;i++){
			for(int j=0;j<9;j++){
				if(b.validMove(i,j)){
					total=analizzaCasi(b,i,j);
				}
			}
		}
		/*for(int i=2;i<9;i+=3){
			for(int j=2;j<9;j+=3) {
				total += fit(b, i - 2, i, j - 2, j);
			}
		}*/
		return total;
	}

	private double analizzaCasi(Board b ,int i, int j) {
		int c=0;
		if(i==0){ //prima riga
			if(j==0){
				if(b.getCol(0,1)!=-1) c++;
				if(b.getCol(1,0)!=-1) c++;
			}
			else if(j==8){
				if(b.getCol(0,7)!=-1) c++;
				if(b.getCol(1,8)!=-1) c++;
			}
			else{
				if(b.getCol(0,j-1)!=-1) c++;
				if(b.getCol(0,j+1)!=-1) c++;
				if(b.getCol(1,j)!=-1) c++;
			}
		}
		else if(i==8){//ultima riga
			if(j==0){
				if(b.getCol(7,0)!=-1) c++;
				if(b.getCol(8,1)!=-1) c++;
			}
			else if(j==8){
				if(b.getCol(8,7)!=-1) c++;
				if(b.getCol(7,8)!=-1) c++;
			}
			else{
				if(b.getCol(7,j)!=-1) c++;
				if(b.getCol(8,j-1)!=-1) c++;
				if(b.getCol(8,j+1)!=-1) c++;
			}
		}
		else if(j==0){//prima colonna
			if(b.getCol(i-1,0)!=-1) c++;
			if(b.getCol(i,1)!=-1) c++;
			if(b.getCol(i+1,0)!=-1) c++;
		}
		else if(j==8){//ultima colonna
			if(b.getCol(i-1,8)!=-1) c++;
			if(b.getCol(i,7)!=-1) c++;
			if(b.getCol(i+1,8)!=-1) c++;
		}
		else{
			if(b.getCol(i-1,j)!=-1) c++;
			if(b.getCol(i,j+1)!=-1) c++;
			if(b.getCol(i+1,j)!=-1) c++;
			if(b.getCol(i,j-1)!=-1) c++;
		}
		if(c==4) return c*-50000D;
		else if(c==2) return c*-25000D;
		else{
			Random r =new Random();
			return r.nextDouble()*100000D;
		}
	}

	private double lastPhase(Board b, int col){
		ArrayList<Node> child = b.getSons((byte)col);
		for (Node n:child){
			if(contaValide(n.getBoard())%2!=0)
				return -100000D;
		}
		return 1000000D;
	}

	private boolean checkSecondPhase(Board b){
		if(contaValide(b)>10) return true;
		else{
			secondaFase=false;
			return false;
		}
	}

	private int contaValide(Board b){
		int count=0;
		for (int i=0;i<9;i++){
			for(int j=0;j<9;j++){
				if (b.validMove(i,j)) count++;
			}
		}
		return count;
	}



	private double fit(Board b,int cs,int ce,int rs,int re){
	//al momento conta le caselle libere di una 3x3
		double freecell=0;
		for(int i=rs;i<re;i++){
			for(int j=cs;j<ce;j++){
				if(b.validMove(i,j)) {
					freecell++;
				}
			}
		}
		return freecell*10;
	}

	@Override
	public int hashCode() {
		return this.toString().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (obj == null) return false;
		if (!(obj instanceof MyHeuristic) ) return false;
		MyHeuristic other = (MyHeuristic) obj;
		return other.toString().equals(this.toString());
	}

}
