package hadron;

import hadron.board.Board;
import hadron.board.ByteBoard;
import hadron.heuristic.GenericHeuristic;
import hadron.heuristic.Heuristic;
import hadron.heuristic.MyHeuristic;
import hadron.research.GameController;
import hadron.research.GameControllerImpl;
import hadron.research.NegaSort;
import hadron.research.Research;

public class DummyPlayer {
	private Heuristic heuristic;
	private GameController game;

	public DummyPlayer(Heuristic h) {
		this.heuristic = h;
	}

	
	public void start(String ip, int port) {
		Board board = new ByteBoard();
		Research algorithm = new NegaSort();
		game = new GameControllerImpl(algorithm, heuristic, board, (byte)0, 930);
		new Communication(ip,port,game);
	}
	
	public static void main(String[] args) {
		Heuristic h = new GenericHeuristic();
		DummyPlayer p1 = new DummyPlayer(h);
		//p1.start("127.0.0.1", 8901);
		p1.start(args[0], Integer.parseInt(args[1]));

	}
	
	public GameController getGame() {
		return this.game;
	}
}