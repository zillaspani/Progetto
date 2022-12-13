package hadron.heuristic;

import hadron.board.Board;

import java.util.*;

public class GenericHeuristic implements Heuristic {
	private static final long serialVersionUID = 5783084660998719046L;

	/**
	 * Costruttore euristica
	 */
	public GenericHeuristic() {
	}


	@Override
	public double evaluate(Board b, int col) {
		/*System.out.println("Col passato: "+col);
		System.out.println("White con getCol:"+b.getCol(0,0));
		System.out.println("White con getPawn:"+b.getPawn(0,0));
		System.out.println("Posizione vuota con getCol: "+b.getCol(0,1));
		System.out.println("Posizione vuota con getPown: "+b.getPawn(0,1));*/
		Random rnd = new Random();
		if(b.isFinal())
			return -1000000D;
		return  rnd.nextDouble()*10000;
	}

	
	@Override
	public int hashCode() {
		return this.toString().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (obj == null) return false;
		if (!(obj instanceof GenericHeuristic) ) return false;
		GenericHeuristic other = (GenericHeuristic) obj;
		return other.toString().equals(this.toString());
	}

}
